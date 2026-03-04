"""
Optimized Authentication Module
Contains: JWT Authentication, Rate Limiting, Email Services, OAuth, Cookie Helpers
"""
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.contrib.auth import get_user_model

from rest_framework import status
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken

from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

User = get_user_model()

# Cache JWT settings to avoid repeated dict lookups
_JWT_SETTINGS = None

def get_jwt_settings():
    """Cache and return JWT settings"""
    global _JWT_SETTINGS
    if _JWT_SETTINGS is None:
        _JWT_SETTINGS = settings.SIMPLE_JWT
    return _JWT_SETTINGS


# ============================================================================
# JWT COOKIE HELPERS
# ============================================================================

def set_jwt_cookies(response, access_token, refresh_token):
    """Set JWT tokens as httpOnly cookies - optimized with cached settings"""
    jwt_settings = get_jwt_settings()
    
    cookie_config = {
        'httponly': jwt_settings.get('AUTH_COOKIE_HTTP_ONLY', True),
        'secure': jwt_settings.get('AUTH_COOKIE_SECURE', False),
        'samesite': jwt_settings.get('AUTH_COOKIE_SAMESITE', 'Lax'),
        'path': jwt_settings.get('AUTH_COOKIE_PATH', '/'),
    }
    
    # Access token
    response.set_cookie(
        key=jwt_settings.get('AUTH_COOKIE', 'access_token'),
        value=access_token,
        max_age=int(jwt_settings['ACCESS_TOKEN_LIFETIME'].total_seconds()),
        **cookie_config
    )
    
    # Refresh token
    response.set_cookie(
        key=jwt_settings.get('AUTH_COOKIE_REFRESH', 'refresh_token'),
        value=refresh_token,
        max_age=int(jwt_settings['REFRESH_TOKEN_LIFETIME'].total_seconds()),
        **cookie_config
    )


def clear_jwt_cookies(response):
    """Clear all authentication cookies with matching attributes for proper deletion"""
    jwt_settings = get_jwt_settings()
    path = jwt_settings.get('AUTH_COOKIE_PATH', '/')
    samesite = jwt_settings.get('AUTH_COOKIE_SAMESITE', 'Lax')
    
    # Delete access token cookie (samesite must match the value used when setting)
    response.delete_cookie(
        jwt_settings.get('AUTH_COOKIE', 'access_token'),
        path=path,
        samesite=samesite,
    )
    
    # Delete refresh token cookie
    response.delete_cookie(
        jwt_settings.get('AUTH_COOKIE_REFRESH', 'refresh_token'),
        path=path,
        samesite=samesite,
    )
    
    # Delete CSRF cookie
    response.delete_cookie(
        settings.CSRF_COOKIE_NAME,
        path='/',
        samesite=settings.CSRF_COOKIE_SAMESITE,
    )
    
    # Delete session cookie
    response.delete_cookie(
        settings.SESSION_COOKIE_NAME,
        path='/',
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )


# ============================================================================
# JWT COOKIE AUTHENTICATION
# ============================================================================

class JWTCookieAuthentication(JWTAuthentication):
    """Custom JWT authentication reading from httpOnly cookie with header fallback"""
    
    def authenticate(self, request):
        # Try cookie first (primary method)
        jwt_settings = get_jwt_settings()
        raw_token = request.COOKIES.get(jwt_settings.get('AUTH_COOKIE', 'access_token'))
        
        # Fallback to Authorization header
        if not raw_token:
            header = self.get_header(request)
            if header:
                raw_token = self.get_raw_token(header)
        
        if not raw_token:
            return None
        
        validated_token = self.get_validated_token(raw_token)
        return self.get_user(validated_token), validated_token


# ============================================================================
# RATE LIMITING
# ============================================================================

class LoginRateThrottle(AnonRateThrottle):
    """10 login attempts per hour per IP"""
    scope = 'login'


class RegisterRateThrottle(AnonRateThrottle):
    """3 registrations per hour per IP"""
    scope = 'register'


class PasswordResetRateThrottle(AnonRateThrottle):
    """10 password reset requests per hour per IP"""
    scope = 'password_reset'


class OTPVerificationRateThrottle(AnonRateThrottle):
    """10 OTP verifications per hour per IP"""
    scope = 'otp_verify'


# ============================================================================
# EMAIL SERVICES
# ============================================================================

def send_verification_email(user):
    """Create and send email verification OTP"""
    from .models import OTPCode
    otp = OTPCode.create_otp(user, 'email_verification', expiry_minutes=10)
    send_otp_email(user, otp.plain_code, 'email_verification')


def send_otp_email(user, otp_code, purpose='password_reset'):
    """Send OTP code via email with template"""
    purpose_titles = {
        'password_reset': 'Password Reset',
        'email_verification': 'Email Verification',
        'two_factor': 'Two-Factor Authentication'
    }
    
    context = {
        'user': user,
        'otp_code': otp_code,
        'expiry_minutes': 10,
        'purpose': purpose,
    }
    
    html_message = render_to_string('emails/otp_email.html', context)
    
    send_mail(
        subject=f'{purpose_titles.get(purpose, "Verification")} - Secure Auth',
        message=strip_tags(html_message),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        html_message=html_message,
        fail_silently=False,
    )


def send_welcome_email(user):
    """Send welcome email after verification"""
    context = {
        'user': user,
        'login_url': f"{settings.CORS_ALLOWED_ORIGINS[0]}/login" if settings.CORS_ALLOWED_ORIGINS else '#',
    }
    
    html_message = render_to_string('emails/welcome_email.html', context)
    
    send_mail(
        subject='Welcome to Secure Auth - Your Account is Ready',
        message=strip_tags(html_message),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        html_message=html_message,
        fail_silently=False,
    )


# ============================================================================
# GOOGLE OAUTH2 AUTHENTICATION
# ============================================================================

def google_login_view(request):
    """
    Authenticate user with Google OAuth2 token.
    
    Enterprise security:
    - Validates issuer, audience, and email_verified claims
    - Enforces MFA if the user has it enabled (Google login does NOT bypass MFA)
    - Rejects tokens older than 5 minutes to limit replay window
    - Handles username collisions with IntegrityError fallback
    - Never leaks internal error details
    """
    import time
    from django.db import IntegrityError

    token = request.data.get('token')
    if not token:
        return Response({'error': 'Google token is required'}, status=status.HTTP_400_BAD_REQUEST)
    
    google_client_id = settings.GOOGLE_OAUTH_CLIENT_ID
    if not google_client_id:
        return Response({'error': 'Google OAuth not configured'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    try:
        # Verify Google token (validates audience=client_id automatically)
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), google_client_id)
        
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            return Response({'error': 'Authentication failed'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Reject tokens older than 5 minutes to limit replay window
        issued_at = idinfo.get('iat', 0)
        if time.time() - issued_at > 300:
            return Response({'error': 'Authentication failed'}, status=status.HTTP_400_BAD_REQUEST)
        
        email = idinfo.get('email')
        email_verified = idinfo.get('email_verified', False)
        
        if not email or not email_verified:
            return Response({'error': 'A verified email is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        given_name = idinfo.get('given_name', '')
        family_name = idinfo.get('family_name', '')
        
        # Get or create user — handle username collision via IntegrityError
        base_username = email.split('@')[0]
        try:
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    'username': base_username,
                    'first_name': given_name,
                    'last_name': family_name,
                    'is_verified': True,  # Google-verified emails are trusted
                }
            )
        except IntegrityError:
            # Username collision — retry with a numbered suffix
            import secrets
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    'username': f"{base_username}_{secrets.token_hex(4)}",
                    'first_name': given_name,
                    'last_name': family_name,
                    'is_verified': True,
                }
            )
        
        # New Google-OAuth users should NOT have a usable password
        if created:
            user.set_unusable_password()
            user.save(update_fields=['password'])
        
        # Update existing user if needed
        if not created:
            update_fields = []
            if not user.first_name and given_name:
                user.first_name = given_name
                update_fields.append('first_name')
            if not user.last_name and family_name:
                user.last_name = family_name
                update_fields.append('last_name')
            if not user.is_verified:
                user.is_verified = True
                update_fields.append('is_verified')
            if update_fields:
                user.save(update_fields=update_fields)
        
        # ---- MFA enforcement: Google login does NOT bypass TOTP ----
        if user.mfa_enabled and user.get_mfa_secret():
            return Response({
                'mfa_required': True,
                'email': email,
                'message': 'Please enter your MFA code from Google Authenticator',
            }, status=status.HTTP_200_OK)
        
        # Generate tokens and respond
        refresh = RefreshToken.for_user(user)
        from .serializers import UserSerializer
        
        response = Response({'user': UserSerializer(user).data})
        set_jwt_cookies(response, str(refresh.access_token), str(refresh))
        return response
    
    except ValueError:
        # google-auth raises ValueError for invalid/expired tokens
        return Response({'error': 'Authentication failed'}, status=status.HTTP_400_BAD_REQUEST)
    except Exception:
        return Response({'error': 'Authentication failed. Please try again.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
