from datetime import datetime
from enum import Enum
from typing import Optional
from dataclasses import dataclass
import hashlib
import secrets

class UserRole(Enum):
    ADMIN = "admin"
    USER = "user"
    SUPPORT = "support"

class UserStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    EXPIRED = "expired"

@dataclass
class User:
    id: str
    username: str
    email: str
    password_hash: str
    role: UserRole
    status: UserStatus
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None
    expire_date: Optional[datetime] = None
    
    def validate(self) -> bool:
        return bool(self.username and self.email and self.password_hash)
    
    def is_active(self) -> bool:
        return self.status == UserStatus.ACTIVE
    
    def has_expired(self) -> bool:
        if not self.expire_date:
            return False
        return datetime.now() > self.expire_date
    
    def can_access(self, resource: str) -> bool:
        if self.role == UserRole.ADMIN:
            return True
        if resource == "profile" and self.role in [UserRole.USER, UserRole.SUPPORT]:
            return True
        return False
    
    def update_last_login(self):
        self.last_login = datetime.now()
    
    def change_password(self, new_password: str) -> bool:
        salt = secrets.token_hex(16)
        self.password_hash = hashlib.sha256((new_password + salt).encode()).hexdigest()
        self.updated_at = datetime.now()
        return True
    
    @staticmethod
    def hash_password(password: str) -> str:
        salt = secrets.token_hex(16)
        return hashlib.sha256((password + salt).encode()).hexdigest() 