from datetime import datetime
from typing import List, Optional
import uuid
from ...domain.entities.vpn_server import VPNServer, ProtocolType, ServerStatus
from ...domain.repositories.server_repository import ServerRepository
from ...infrastructure.protocols.wireguard import WireGuardProtocol
from ...infrastructure.protocols.openvpn import OpenVPNProtocol

class CreateServerUseCase:
    def __init__(self, server_repository: ServerRepository):
        self.server_repository = server_repository
        self.wireguard_protocol = WireGuardProtocol()
        self.openvpn_protocol = OpenVPNProtocol()
    
    def execute(self, name: str, protocol: str, port: int, interface: str = None) -> Optional[VPNServer]:
        if self.server_repository.find_by_name(name):
            return None
        
        if self.server_repository.find_by_port(port):
            return None
        
        if not interface:
            interface = name
        
        server = VPNServer(
            id=str(uuid.uuid4()),
            name=name,
            protocol=ProtocolType(protocol),
            port=port,
            interface=interface,
            private_key="",
            public_key="",
            status=ServerStatus.STOPPED,
            config_path="",
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        server.generate_keys()
        
        if protocol == "wireguard":
            success = self.wireguard_protocol.create_server(server)
        elif protocol == "openvpn":
            success = self.openvpn_protocol.create_server(server)
            if success:
                success = self.openvpn_protocol.generate_certificates(server)
        else:
            return None
        
        if success and self.server_repository.save(server):
            return server
        return None

class StartServerUseCase:
    def __init__(self, server_repository: ServerRepository):
        self.server_repository = server_repository
        self.wireguard_protocol = WireGuardProtocol()
        self.openvpn_protocol = OpenVPNProtocol()
    
    def execute(self, server_id: str) -> bool:
        server = self.server_repository.find_by_id(server_id)
        if not server:
            return False
        
        if server.protocol == ProtocolType.WIREGUARD:
            success = self.wireguard_protocol.start_server(server)
        elif server.protocol == ProtocolType.OPENVPN:
            success = self.openvpn_protocol.start_server(server)
        else:
            return False
        
        if success:
            server.status = ServerStatus.RUNNING
            server.updated_at = datetime.now()
            return self.server_repository.update(server)
        return False

class StopServerUseCase:
    def __init__(self, server_repository: ServerRepository):
        self.server_repository = server_repository
        self.wireguard_protocol = WireGuardProtocol()
        self.openvpn_protocol = OpenVPNProtocol()
    
    def execute(self, server_id: str) -> bool:
        server = self.server_repository.find_by_id(server_id)
        if not server:
            return False
        
        if server.protocol == ProtocolType.WIREGUARD:
            success = self.wireguard_protocol.stop_server(server)
        elif server.protocol == ProtocolType.OPENVPN:
            success = self.openvpn_protocol.stop_server(server)
        else:
            return False
        
        if success:
            server.status = ServerStatus.STOPPED
            server.updated_at = datetime.now()
            return self.server_repository.update(server)
        return False

class RestartServerUseCase:
    def __init__(self, server_repository: ServerRepository):
        self.server_repository = server_repository
        self.wireguard_protocol = WireGuardProtocol()
        self.openvpn_protocol = OpenVPNProtocol()
    
    def execute(self, server_id: str) -> bool:
        server = self.server_repository.find_by_id(server_id)
        if not server:
            return False
        
        if server.protocol == ProtocolType.WIREGUARD:
            success = self.wireguard_protocol.restart()
        elif server.protocol == ProtocolType.OPENVPN:
            success = self.openvpn_protocol.restart()
        else:
            return False
        
        if success:
            server.updated_at = datetime.now()
            return self.server_repository.update(server)
        return False

class GetServerUseCase:
    def __init__(self, server_repository: ServerRepository):
        self.server_repository = server_repository
    
    def execute(self, server_id: str) -> Optional[VPNServer]:
        return self.server_repository.find_by_id(server_id)
    
    def by_name(self, name: str) -> Optional[VPNServer]:
        return self.server_repository.find_by_name(name)
    
    def by_port(self, port: int) -> Optional[VPNServer]:
        return self.server_repository.find_by_port(port)

class ListServersUseCase:
    def __init__(self, server_repository: ServerRepository):
        self.server_repository = server_repository
    
    def execute(self, protocol: Optional[str] = None) -> List[VPNServer]:
        if protocol:
            return self.server_repository.find_by_protocol(ProtocolType(protocol))
        return self.server_repository.find_all()
    
    def running_servers(self) -> List[VPNServer]:
        return self.server_repository.find_running_servers()

class DeleteServerUseCase:
    def __init__(self, server_repository: ServerRepository):
        self.server_repository = server_repository
        self.wireguard_protocol = WireGuardProtocol()
        self.openvpn_protocol = OpenVPNProtocol()
    
    def execute(self, server_id: str) -> bool:
        server = self.server_repository.find_by_id(server_id)
        if not server:
            return False
        
        if server.status == ServerStatus.RUNNING:
            if server.protocol == ProtocolType.WIREGUARD:
                self.wireguard_protocol.stop_server(server)
            elif server.protocol == ProtocolType.OPENVPN:
                self.openvpn_protocol.stop_server(server)
        
        return self.server_repository.delete(server_id)

class GetServerStatusUseCase:
    def __init__(self, server_repository: ServerRepository):
        self.server_repository = server_repository
        self.wireguard_protocol = WireGuardProtocol()
        self.openvpn_protocol = OpenVPNProtocol()
    
    def execute(self, server_id: str) -> dict:
        server = self.server_repository.find_by_id(server_id)
        if not server:
            return {"status": "not_found"}
        
        if server.protocol == ProtocolType.WIREGUARD:
            return self.wireguard_protocol.get_server_status(server)
        elif server.protocol == ProtocolType.OPENVPN:
            return self.openvpn_protocol.get_server_status(server)
        else:
            return {"status": "unknown_protocol"} 