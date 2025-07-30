from datetime import datetime, timedelta
from typing import Optional
import jwt
import bcrypt
from ..entities.user import User, UserRole, UserStatus
from ..repositories.user_repository import UserRepository

class AuthService:
    def __init__(self, user_repository: UserRepository, secret_key: str):
        self.user_repository = user_repository
        self.secret_key = secret_key
        self.algorithm = "HS256"
        self.access_token_expire_minutes = 30
    
    def hash_password(self, password: str) -> str:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        user = self.user_repository.find_by_username(username)
        if not user:
            return None
        
        if not self.verify_password(password, user.password_hash):
            return None
        
        if not user.is_active():
            return None
        
        if user.has_expired():
            return None
        
        return user
    
    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def verify_token(self, token: str) -> Optional[dict]:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            username: str = payload.get("sub")
            if username is None:
                return None
            return payload
        except jwt.PyJWTError:
            return None
    
    def get_current_user(self, token: str) -> Optional[User]:
        payload = self.verify_token(token)
        if payload is None:
            return None
        
        username: str = payload.get("sub")
        if username is None:
            return None
        
        user = self.user_repository.find_by_username(username)
        if user is None:
            return None
        
        return user
    
    def require_admin(self, user: User) -> bool:
        return user.role == UserRole.ADMIN 