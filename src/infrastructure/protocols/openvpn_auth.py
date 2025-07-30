import subprocess
import os
import tempfile
import hashlib
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

@dataclass
class OpenVPNUser:
    username: str
    password_hash: str
    client_id: str
    server_id: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]
    bandwidth_limit: int  # Mbps
    daily_limit: int      # GB

class OpenVPNAuthManager:
    def __init__(self, auth_file: str = "/etc/openvpn/auth.txt"):
        self.auth_file = auth_file
        self.users: Dict[str, OpenVPNUser] = {}
        self.logger = logging.getLogger(__name__)
        self._load_users()
    
    def _load_users(self):
        """Load users from auth file"""
        if os.path.exists(self.auth_file):
            try:
                with open(self.auth_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            parts = line.split(':')
                            if len(parts) >= 2:
                                username = parts[0]
                                password_hash = parts[1]
                                # Load additional user data from database or config
                                self.users[username] = OpenVPNUser(
                                    username=username,
                                    password_hash=password_hash,
                                    client_id="",
                                    server_id="",
                                    is_active=True,
                                    created_at=datetime.now(),
                                    last_login=None,
                                    bandwidth_limit=0,
                                    daily_limit=0
                                )
            except Exception as e:
                self.logger.error(f"Error loading users: {e}")
    
    def _save_users(self):
        """Save users to auth file"""
        try:
            with open(self.auth_file, 'w') as f:
                f.write("# OpenVPN User Authentication File\n")
                f.write("# Format: username:password_hash\n\n")
                for user in self.users.values():
                    f.write(f"{user.username}:{user.password_hash}\n")
            os.chmod(self.auth_file, 0o600)
        except Exception as e:
            self.logger.error(f"Error saving users: {e}")
    
    def create_user(self, username: str, password: str, client_id: str = "", 
                   server_id: str = "", bandwidth_limit: int = 0, 
                   daily_limit: int = 0) -> bool:
        """Create a new OpenVPN user"""
        try:
            if username in self.users:
                return False
            
            # Hash password
            password_hash = self._hash_password(password)
            
            # Create user
            user = OpenVPNUser(
                username=username,
                password_hash=password_hash,
                client_id=client_id,
                server_id=server_id,
                is_active=True,
                created_at=datetime.now(),
                last_login=None,
                bandwidth_limit=bandwidth_limit,
                daily_limit=daily_limit
            )
            
            self.users[username] = user
            self._save_users()
            
            self.logger.info(f"OpenVPN user created: {username}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating user {username}: {e}")
            return False
    
    def authenticate_user(self, username: str, password: str) -> Tuple[bool, str]:
        """Authenticate OpenVPN user"""
        try:
            if username not in self.users:
                return False, "User not found"
            
            user = self.users[username]
            
            if not user.is_active:
                return False, "User account disabled"
            
            # Verify password
            if not self._verify_password(password, user.password_hash):
                return False, "Invalid password"
            
            # Update last login
            user.last_login = datetime.now()
            
            # Check bandwidth limits
            if not self._check_bandwidth_limits(user):
                return False, "Bandwidth limit exceeded"
            
            self.logger.info(f"OpenVPN user authenticated: {username}")
            return True, "Authentication successful"
            
        except Exception as e:
            self.logger.error(f"Error authenticating user {username}: {e}")
            return False, "Authentication error"
    
    def delete_user(self, username: str) -> bool:
        """Delete OpenVPN user"""
        try:
            if username not in self.users:
                return False
            
            del self.users[username]
            self._save_users()
            
            self.logger.info(f"OpenVPN user deleted: {username}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error deleting user {username}: {e}")
            return False
    
    def update_user_password(self, username: str, new_password: str) -> bool:
        """Update user password"""
        try:
            if username not in self.users:
                return False
            
            user = self.users[username]
            user.password_hash = self._hash_password(new_password)
            self._save_users()
            
            self.logger.info(f"Password updated for user: {username}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error updating password for user {username}: {e}")
            return False
    
    def set_user_bandwidth_limit(self, username: str, bandwidth_limit: int, 
                                daily_limit: int = 0) -> bool:
        """Set bandwidth limits for user"""
        try:
            if username not in self.users:
                return False
            
            user = self.users[username]
            user.bandwidth_limit = bandwidth_limit
            user.daily_limit = daily_limit
            
            self.logger.info(f"Bandwidth limits set for user {username}: {bandwidth_limit}Mbps, {daily_limit}GB daily")
            return True
            
        except Exception as e:
            self.logger.error(f"Error setting bandwidth limits for user {username}: {e}")
            return False
    
    def disable_user(self, username: str) -> bool:
        """Disable user account"""
        try:
            if username not in self.users:
                return False
            
            self.users[username].is_active = False
            self.logger.info(f"User disabled: {username}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error disabling user {username}: {e}")
            return False
    
    def enable_user(self, username: str) -> bool:
        """Enable user account"""
        try:
            if username not in self.users:
                return False
            
            self.users[username].is_active = True
            self.logger.info(f"User enabled: {username}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error enabling user {username}: {e}")
            return False
    
    def get_user_stats(self, username: str) -> Dict[str, any]:
        """Get user statistics"""
        if username not in self.users:
            return {}
        
        user = self.users[username]
        return {
            "username": user.username,
            "is_active": user.is_active,
            "created_at": user.created_at.isoformat(),
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "bandwidth_limit": user.bandwidth_limit,
            "daily_limit": user.daily_limit
        }
    
    def get_all_users(self) -> List[OpenVPNUser]:
        """Get all users"""
        return list(self.users.values())
    
    def _hash_password(self, password: str) -> str:
        """Hash password using SHA256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        return self._hash_password(password) == password_hash
    
    def _check_bandwidth_limits(self, user: OpenVPNUser) -> bool:
        """Check if user has exceeded bandwidth limits"""
        # This would integrate with the bandwidth manager
        # For now, return True
        return True
    
    def create_auth_script(self) -> str:
        """Create OpenVPN auth script"""
        script_content = f"""#!/bin/bash
# OpenVPN Authentication Script
# Generated by VPN Panel

AUTH_FILE="{self.auth_file}"

# Read username and password from environment
USERNAME="$1"
PASSWORD="$2"

# Check if user exists and password is correct
if grep -q "^$USERNAME:" "$AUTH_FILE"; then
    STORED_HASH=$(grep "^$USERNAME:" "$AUTH_FILE" | cut -d: -f2)
    INPUT_HASH=$(echo -n "$PASSWORD" | sha256sum | cut -d' ' -f1)
    
    if [ "$STORED_HASH" = "$INPUT_HASH" ]; then
        echo "OK"
        exit 0
    fi
fi

echo "FAIL"
exit 1
"""
        
        script_path = "/etc/openvpn/auth.sh"
        try:
            with open(script_path, 'w') as f:
                f.write(script_content)
            os.chmod(script_path, 0o755)
            return script_path
        except Exception as e:
            self.logger.error(f"Error creating auth script: {e}")
            return ""

# Global OpenVPN auth manager instance
openvpn_auth_manager = OpenVPNAuthManager() 