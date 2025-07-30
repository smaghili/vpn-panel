import secrets
import hashlib
import base64
import os
import json
import logging
from pathlib import Path
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class SecretManager:
    """Manages automatic generation and storage of secret keys"""
    
    def __init__(self, secrets_file: str = "/etc/vpn-panel/secrets.json"):
        self.secrets_file = Path(secrets_file)
        self.logger = logging.getLogger(__name__)
        self.secrets = {}
        self._load_or_generate_secrets()
    
    def _load_or_generate_secrets(self):
        """Load existing secrets or generate new ones"""
        if self.secrets_file.exists():
            try:
                with open(self.secrets_file, 'r') as f:
                    self.secrets = json.load(f)
                self.logger.info("Loaded existing secrets")
            except Exception as e:
                self.logger.error(f"Error loading secrets: {e}")
                self._generate_new_secrets()
        else:
            self._generate_new_secrets()
    
    def _generate_new_secrets(self):
        """Generate new secret keys"""
        self.logger.info("Generating new secret keys")
        
        # Generate JWT secret key (64 bytes = 512 bits)
        self.secrets['jwt_secret'] = secrets.token_urlsafe(64)
        
        # Generate session secret (32 bytes = 256 bits)
        self.secrets['session_secret'] = secrets.token_urlsafe(32)
        
        # Generate encryption key for sensitive data
        self.secrets['encryption_key'] = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
        
        # Generate API key for external integrations
        self.secrets['api_key'] = secrets.token_urlsafe(32)
        
        # Generate CSRF token secret
        self.secrets['csrf_secret'] = secrets.token_urlsafe(32)
        
        # Generate password reset token secret
        self.secrets['password_reset_secret'] = secrets.token_urlsafe(32)
        
        # Generate WebSocket secret
        self.secrets['websocket_secret'] = secrets.token_urlsafe(32)
        
        # Generate admin token secret
        self.secrets['admin_token_secret'] = secrets.token_urlsafe(32)
        
        # Generate backup encryption key
        self.secrets['backup_key'] = secrets.token_urlsafe(32)
        
        # Save secrets
        self._save_secrets()
        
        self.logger.info("Generated and saved new secret keys")
    
    def _save_secrets(self):
        """Save secrets to file"""
        try:
            # Ensure directory exists
            self.secrets_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Save with restricted permissions
            with open(self.secrets_file, 'w') as f:
                json.dump(self.secrets, f, indent=2)
            
            # Set file permissions to 600 (owner read/write only)
            os.chmod(self.secrets_file, 0o600)
            
            self.logger.info(f"Secrets saved to {self.secrets_file}")
        except Exception as e:
            self.logger.error(f"Error saving secrets: {e}")
            raise
    
    def get_secret(self, key: str) -> str:
        """Get a specific secret key"""
        if key not in self.secrets:
            raise KeyError(f"Secret key '{key}' not found")
        return self.secrets[key]
    
    def get_jwt_secret(self) -> str:
        """Get JWT secret key"""
        return self.get_secret('jwt_secret')
    
    def get_session_secret(self) -> str:
        """Get session secret"""
        return self.get_secret('session_secret')
    
    def get_encryption_key(self) -> str:
        """Get encryption key"""
        return self.get_secret('encryption_key')
    
    def get_api_key(self) -> str:
        """Get API key"""
        return self.get_secret('api_key')
    
    def get_csrf_secret(self) -> str:
        """Get CSRF secret"""
        return self.get_secret('csrf_secret')
    
    def get_password_reset_secret(self) -> str:
        """Get password reset secret"""
        return self.get_secret('password_reset_secret')
    
    def get_websocket_secret(self) -> str:
        """Get WebSocket secret"""
        return self.get_secret('websocket_secret')
    
    def get_admin_token_secret(self) -> str:
        """Get admin token secret"""
        return self.get_secret('admin_token_secret')
    
    def get_backup_key(self) -> str:
        """Get backup encryption key"""
        return self.get_secret('backup_key')
    
    def rotate_secret(self, key: str):
        """Rotate a specific secret key"""
        if key == 'jwt_secret':
            self.secrets[key] = secrets.token_urlsafe(64)
        else:
            self.secrets[key] = secrets.token_urlsafe(32)
        
        self._save_secrets()
        self.logger.info(f"Rotated secret key: {key}")
    
    def rotate_all_secrets(self):
        """Rotate all secret keys"""
        self._generate_new_secrets()
        self.logger.warning("All secret keys have been rotated")
    
    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data using the encryption key"""
        key = base64.urlsafe_b64decode(self.get_encryption_key())
        f = Fernet(key)
        return f.encrypt(data.encode()).decode()
    
    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data using the encryption key"""
        key = base64.urlsafe_b64decode(self.get_encryption_key())
        f = Fernet(key)
        return f.decrypt(encrypted_data.encode()).decode()
    
    def generate_secure_token(self, length: int = 32) -> str:
        """Generate a secure random token"""
        return secrets.token_urlsafe(length)
    
    def generate_secure_password(self, length: int = 16) -> str:
        """Generate a secure random password"""
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    def hash_password(self, password: str, salt: Optional[str] = None) -> tuple[str, str]:
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(16)
        
        # Use PBKDF2 for password hashing
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode(),
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key.decode(), salt
    
    def verify_password(self, password: str, hashed_password: str, salt: str) -> bool:
        """Verify password against hash"""
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt.encode(),
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            return key.decode() == hashed_password
        except Exception:
            return False
    
    def get_secrets_summary(self) -> dict:
        """Get summary of secrets (without revealing actual values)"""
        summary = {}
        for key, value in self.secrets.items():
            summary[key] = {
                "length": len(value),
                "type": "urlsafe",
                "exists": True
            }
        return summary
    
    def backup_secrets(self, backup_path: str):
        """Backup secrets to a secure location"""
        try:
            backup_file = Path(backup_path)
            backup_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(backup_file, 'w') as f:
                json.dump(self.secrets, f, indent=2)
            
            os.chmod(backup_file, 0o600)
            self.logger.info(f"Secrets backed up to {backup_path}")
        except Exception as e:
            self.logger.error(f"Error backing up secrets: {e}")
            raise
    
    def restore_secrets(self, backup_path: str):
        """Restore secrets from backup"""
        try:
            with open(backup_path, 'r') as f:
                self.secrets = json.load(f)
            
            self._save_secrets()
            self.logger.info(f"Secrets restored from {backup_path}")
        except Exception as e:
            self.logger.error(f"Error restoring secrets: {e}")
            raise

# Global secret manager instance
secret_manager = SecretManager() 