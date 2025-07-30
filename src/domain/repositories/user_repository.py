from abc import ABC, abstractmethod
from typing import List, Optional
from ..entities.user import User

class UserRepository(ABC):
    @abstractmethod
    def save(self, user: User) -> bool:
        pass
    
    @abstractmethod
    def find_by_id(self, user_id: str) -> Optional[User]:
        pass
    
    @abstractmethod
    def find_by_username(self, username: str) -> Optional[User]:
        pass
    
    @abstractmethod
    def find_by_email(self, email: str) -> Optional[User]:
        pass
    
    @abstractmethod
    def find_all(self) -> List[User]:
        pass
    
    @abstractmethod
    def find_by_role(self, role: str) -> List[User]:
        pass
    
    @abstractmethod
    def find_active_users(self) -> List[User]:
        pass
    
    @abstractmethod
    def delete(self, user_id: str) -> bool:
        pass
    
    @abstractmethod
    def update(self, user: User) -> bool:
        pass
    
    @abstractmethod
    def count(self) -> int:
        pass 