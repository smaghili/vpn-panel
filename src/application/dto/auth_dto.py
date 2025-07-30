from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    user: dict

class UserCreateRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str = "user"
    expire_date: Optional[datetime] = None

class UserUpdateRequest(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    status: Optional[str] = None
    expire_date: Optional[datetime] = None

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: str
    status: str
    created_at: datetime
    last_login: Optional[datetime] = None
    expire_date: Optional[datetime] = None

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str 