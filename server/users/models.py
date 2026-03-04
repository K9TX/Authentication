from django.contrib.auth.models import AbstractUser
from django.contrib.auth.hashers import make_password, check_password
from django.db import models
from django.utils import timezone
from datetime import timedelta
import secrets


class User(AbstractUser):
    """Extended User model for secure authentication"""
    
    email = models.EmailField(unique=True, db_index=True)
    is_verified = models.BooleanField(default=False, db_index=True)
    
    # MFA Fields
    mfa_enabled = models.BooleanField(default=False, db_index=True)
    mfa_secret = models.CharField(max_length=256, null=True, blank=True)  # Increased for encrypted data
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['email', 'is_verified']),
            models.Index(fields=['email', 'mfa_enabled']),
        ]
    
    def __str__(self):
        return self.username
    
    def set_mfa_secret(self, plaintext_secret):
        """
        Set MFA secret with encryption
        
        Args:
            plaintext_secret (str): The plaintext MFA secret to encrypt and store
        """
        from .encryption import EncryptionService
        
        if plaintext_secret:
            self.mfa_secret = EncryptionService.encrypt(plaintext_secret)
        else:
            self.mfa_secret = None
    
    def get_mfa_secret(self):
        """
        Get decrypted MFA secret
        
        Returns:
            str: The decrypted MFA secret or None
        """
        from .encryption import EncryptionService
        
        if self.mfa_secret:
            return EncryptionService.decrypt(self.mfa_secret)
        return None


class OTPCode(models.Model):
    """OTP codes for password reset and 2FA - stored as hashes for security"""
    
    PURPOSE_CHOICES = (
        ('password_reset', 'Password Reset'),
        ('email_verification', 'Email Verification'),
        ('two_factor', 'Two Factor Authentication'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='otp_codes')
    code = models.CharField(max_length=128)  # Hashed code
    purpose = models.CharField(max_length=20, choices=PURPOSE_CHOICES, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)
    is_used = models.BooleanField(default=False, db_index=True)
    attempts = models.IntegerField(default=0)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'purpose', 'is_used']),
            models.Index(fields=['expires_at', 'is_used']),
        ]
    
    def __str__(self):
        return f"OTP for {self.user.username} - {self.purpose}"
    
    def is_expired(self):
        """Check if OTP is expired"""
        return timezone.now() > self.expires_at
    
    def is_valid(self):
        """Check if OTP is valid (not used, not expired, attempts < 3)"""
        return not self.is_used and not self.is_expired() and self.attempts < 3
    
    def verify_code(self, plain_code):
        """Verify a plain OTP code against the stored hash"""
        return check_password(plain_code, self.code)
    
    @staticmethod
    def generate_code():
        """Generate a cryptographically secure random 6-digit OTP code"""
        return ''.join(str(secrets.randbelow(10)) for _ in range(6))
    
    @classmethod
    def create_otp(cls, user, purpose, expiry_minutes=10):
        """Create a new OTP for user and invalidate old ones"""
        # Invalidate old OTPs (bulk update for efficiency)
        cls.objects.filter(user=user, purpose=purpose, is_used=False).update(is_used=True)
        
        # Generate new OTP
        plain_code = cls.generate_code()
        hashed_code = make_password(plain_code)
        expires_at = timezone.now() + timedelta(minutes=expiry_minutes)
        
        # Save to database
        otp = cls.objects.create(
            user=user,
            code=hashed_code,
            purpose=purpose,
            expires_at=expires_at
        )
        
        # Attach plain code for email sending
        otp.plain_code = plain_code
        return otp
