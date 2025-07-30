from abc import ABC, abstractmethod
from typing import List, Optional
from ..entities.vpn_server import VPNServer, ProtocolType

class ServerRepository(ABC):
    @abstractmethod
    def save(self, server: VPNServer) -> bool:
        pass
    
    @abstractmethod
    def find_by_id(self, server_id: str) -> Optional[VPNServer]:
        pass
    
    @abstractmethod
    def find_by_name(self, name: str) -> Optional[VPNServer]:
        pass
    
    @abstractmethod
    def find_by_port(self, port: int) -> Optional[VPNServer]:
        pass
    
    @abstractmethod
    def find_by_protocol(self, protocol: ProtocolType) -> List[VPNServer]:
        pass
    
    @abstractmethod
    def find_running_servers(self) -> List[VPNServer]:
        pass
    
    @abstractmethod
    def find_all(self) -> List[VPNServer]:
        pass
    
    @abstractmethod
    def delete(self, server_id: str) -> bool:
        pass
    
    @abstractmethod
    def update(self, server: VPNServer) -> bool:
        pass
    
    @abstractmethod
    def count(self) -> int:
        pass 