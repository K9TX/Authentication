from django.urls import path
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny
from . import views
from .authentication import google_login_view, LoginRateThrottle

# Wrap google_login_view with decorators + rate limiting
@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([LoginRateThrottle])
def google_login(request):
    return google_login_view(request)

urlpatterns = [
    # Authentication
    path('csrf/', views.get_csrf_token, name='get_csrf_token'),
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('google/login/', google_login, name='google_login'),
    path('logout/', views.logout, name='logout'),
    path('me/', views.current_user, name='current_user'),
    path('token/refresh/', views.refresh_token, name='token_refresh'),  
    
    # Email Verification
    path('verify-email-otp/', views.verify_email_otp, name='verify_email_otp'),
    path('resend-verification/', views.resend_verification, name='resend_verification'),
    
    # Password Management
    path('password/reset/request/', views.password_reset_request, name='password_reset_request'),
    path('password/reset/verify/', views.password_reset_verify, name='password_reset_verify'),
    path('password/change/', views.password_change, name='password_change'),

    # MFA (Multi-Factor Authentication)
    path('mfa/setup/', views.mfa_setup, name='mfa_setup'),
    path('mfa/enable/', views.mfa_enable, name='mfa_enable'),
    path('mfa/disable/', views.mfa_disable, name='mfa_disable'),
    path('mfa/verify/', views.mfa_verify_login, name='mfa_verify_login'),
]

