from abc import ABC, abstractmethod
from typing import List, Optional
from ..entities.vpn_client import VPNClient

class ClientRepository(ABC):
    @abstractmethod
    def save(self, client: VPNClient) -> bool:
        pass
    
    @abstractmethod
    def find_by_id(self, client_id: str) -> Optional[VPNClient]:
        pass
    
    @abstractmethod
    def find_by_user_id(self, user_id: str) -> List[VPNClient]:
        pass
    
    @abstractmethod
    def find_by_server_id(self, server_id: str) -> List[VPNClient]:
        pass
    
    @abstractmethod
    def find_active_clients(self) -> List[VPNClient]:
        pass
    
    @abstractmethod
    def find_expired_clients(self) -> List[VPNClient]:
        pass
    
    @abstractmethod
    def find_by_bandwidth_exceeded(self) -> List[VPNClient]:
        pass
    
    @abstractmethod
    def find_all(self) -> List[VPNClient]:
        pass
    
    @abstractmethod
    def delete(self, client_id: str) -> bool:
        pass
    
    @abstractmethod
    def update(self, client: VPNClient) -> bool:
        pass
    
    @abstractmethod
    def count(self) -> int:
        pass 