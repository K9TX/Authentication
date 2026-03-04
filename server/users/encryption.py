"""
Encryption utilities for sensitive data
Provides field-level encryption for MFA secrets and other sensitive information
"""
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from decouple import config
import logging

logger = logging.getLogger(__name__)


class EncryptionService:
    """Service for encrypting and decrypting sensitive data"""
    
    _cipher = None
    
    @classmethod
    def _get_cipher(cls):
        """Get or create Fernet cipher instance"""
        if cls._cipher is None:
            encryption_key = config('MFA_ENCRYPTION_KEY', default=None)
            
            if not encryption_key:
                logger.warning(
                    "MFA_ENCRYPTION_KEY not set in environment. "
                    "MFA secrets will not be encrypted. "
                    "Generate a key with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
                )
                return None
            
            try:
                # Ensure key is bytes
                if isinstance(encryption_key, str):
                    encryption_key = encryption_key.encode()
                
                cls._cipher = Fernet(encryption_key)
            except Exception as e:
                logger.error(f"Failed to initialize encryption cipher: {e}")
                return None
        
        return cls._cipher
    
    @classmethod
    def encrypt(cls, plaintext):
        """
        Encrypt plaintext string
        
        Args:
            plaintext (str): The text to encrypt
            
        Returns:
            str: Encrypted text (base64 encoded) or plaintext if encryption fails
        """
        if not plaintext:
            return plaintext
        
        cipher = cls._get_cipher()
        if not cipher:
            raise ValueError(
                "MFA_ENCRYPTION_KEY is not configured. "
                "MFA secrets cannot be stored without encryption. "
                'Generate a key with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
            )
        
        try:
            # Convert to bytes if string
            if isinstance(plaintext, str):
                plaintext = plaintext.encode()
            
            # Encrypt and return as string
            encrypted = cipher.encrypt(plaintext)
            return encrypted.decode()
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise ValueError(f"Failed to encrypt sensitive data: {e}")
    
    @classmethod
    def decrypt(cls, encrypted_text):
        """
        Decrypt encrypted string
        
        Args:
            encrypted_text (str): The encrypted text to decrypt
            
        Returns:
            str: Decrypted plaintext or encrypted_text if decryption fails
        """
        if not encrypted_text:
            return encrypted_text
        
        cipher = cls._get_cipher()
        if not cipher:
            raise ValueError(
                "MFA_ENCRYPTION_KEY is not configured. "
                "Cannot decrypt MFA secrets without the encryption key."
            )
        
        try:
            # Convert to bytes if string
            if isinstance(encrypted_text, str):
                encrypted_text = encrypted_text.encode()
            
            # Decrypt and return as string
            decrypted = cipher.decrypt(encrypted_text)
            return decrypted.decode()
        except InvalidToken:
            logger.error("Failed to decrypt data - invalid token or wrong key")
            raise ValueError("Failed to decrypt sensitive data. The encryption key may have changed.")
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise ValueError(f"Failed to decrypt sensitive data: {e}")
    
    @classmethod
    def is_encrypted(cls, text):
        """
        Check if text appears to be encrypted (Fernet format)
        
        Args:
            text (str): Text to check
            
        Returns:
            bool: True if text appears to be encrypted
        """
        if not text or not isinstance(text, str):
            return False
        
        # Fernet tokens start with 'gAAAAA' when base64 decoded
        # They are typically 100+ characters long
        return len(text) > 50 and text.startswith('gAAAAA')
