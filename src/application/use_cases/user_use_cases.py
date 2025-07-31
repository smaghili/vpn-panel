from datetime import datetime
from typing import List, Optional
import uuid
from ...domain.entities.user import User, UserRole, UserStatus
from ...domain.repositories.user_repository import UserRepository

class CreateUserUseCase:
    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository
    
    def execute(self, username: str, password: str, role: str = "user") -> Optional[User]:
        if self.user_repository.find_by_username(username):
            return None
        
        user = User(
            id=str(uuid.uuid4()),
            username=username,
            password_hash=User.hash_password(password),
            role=UserRole(role),
            status=UserStatus.ACTIVE,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        if self.user_repository.save(user):
            return user
        return None

class UpdateUserUseCase:
    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository
    
    def execute(self, user_id: str, **kwargs) -> bool:
        user = self.user_repository.find_by_id(user_id)
        if not user:
            return False
        
        if 'username' in kwargs:
            existing_user = self.user_repository.find_by_username(kwargs['username'])
            if existing_user and existing_user.id != user_id:
                return False
            user.username = kwargs['username']
        

        
        if 'role' in kwargs:
            user.role = UserRole(kwargs['role'])
        
        if 'status' in kwargs:
            user.status = UserStatus(kwargs['status'])
        
        if 'expire_date' in kwargs:
            user.expire_date = kwargs['expire_date']
        
        user.updated_at = datetime.now()
        return self.user_repository.update(user)

class DeleteUserUseCase:
    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository
    
    def execute(self, user_id: str) -> bool:
        return self.user_repository.delete(user_id)

class GetUserUseCase:
    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository
    
    def execute(self, user_id: str) -> Optional[User]:
        return self.user_repository.find_by_id(user_id)
    
    def by_username(self, username: str) -> Optional[User]:
        return self.user_repository.find_by_username(username)
    


class ListUsersUseCase:
    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository
    
    def execute(self, role: Optional[str] = None) -> List[User]:
        if role:
            return self.user_repository.find_by_role(role)
        return self.user_repository.find_all()
    
    def active_users(self) -> List[User]:
        return self.user_repository.find_active_users()

class ChangePasswordUseCase:
    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository
    
    def execute(self, user_id: str, new_password: str) -> bool:
        user = self.user_repository.find_by_id(user_id)
        if not user:
            return False
        
        return user.change_password(new_password) and self.user_repository.update(user)

class AuthenticateUserUseCase:
    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository
    
    def execute(self, username: str, password: str) -> Optional[User]:
        user = self.user_repository.find_by_username(username)
        if not user:
            return None
        
        if not user.is_active():
            return None
        
        if user.has_expired():
            return None
        
        if user.password_hash == User.hash_password(password):
            user.update_last_login()
            self.user_repository.update(user)
            return user
        
        return None 