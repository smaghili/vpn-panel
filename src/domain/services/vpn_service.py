from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid
from ..entities.vpn_server import VPNServer, ProtocolType, ServerStatus
from ..entities.vpn_client import VPNClient, ClientStatus
from ..repositories.server_repository import ServerRepository
from ..repositories.client_repository import ClientRepository
from ...infrastructure.protocols.wireguard import WireGuardProtocol
from ...infrastructure.protocols.openvpn import OpenVPNProtocol

class VPNService:
    def __init__(self, server_repository: ServerRepository, client_repository: ClientRepository):
        self.server_repository = server_repository
        self.client_repository = client_repository
        self.wireguard_protocol = WireGuardProtocol()
        self.openvpn_protocol = OpenVPNProtocol()
    
    def create_server(self, name: str, protocol: str, port: int, interface: str = None) -> Optional[VPNServer]:
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
    
    def start_server(self, server_id: str) -> bool:
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
    
    def stop_server(self, server_id: str) -> bool:
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
    
    def get_server_status(self, server_id: str) -> Dict[str, Any]:
        server = self.server_repository.find_by_id(server_id)
        if not server:
            return {"status": "not_found"}
        
        if server.protocol == ProtocolType.WIREGUARD:
            return self.wireguard_protocol.get_server_status(server)
        elif server.protocol == ProtocolType.OPENVPN:
            return self.openvpn_protocol.get_server_status(server)
        else:
            return {"status": "unknown_protocol"}
    
    def create_client(self, user_id: str, server_id: str, name: str, bandwidth_limit: int, expire_date: Optional[datetime] = None) -> Optional[VPNClient]:
        server = self.server_repository.find_by_id(server_id)
        if not server:
            return None
        
        client = VPNClient(
            id=str(uuid.uuid4()),
            user_id=user_id,
            server_id=server_id,
            name=name,
            public_key="",
            private_key="",
            allowed_ips=f"10.0.0.{len(self.client_repository.find_by_server_id(server_id)) + 2}/32",
            bandwidth_limit=bandwidth_limit,
            bandwidth_used=0,
            expire_date=expire_date,
            status=ClientStatus.ACTIVE,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        client.generate_keys()
        
        if server.protocol == ProtocolType.WIREGUARD:
            success = self.wireguard_protocol.add_client(server, client)
        elif server.protocol == ProtocolType.OPENVPN:
            success = self.openvpn_protocol.generate_client_cert(client, server)
        else:
            return None
        
        if success and self.client_repository.save(client):
            return client
        return None
    
    def delete_client(self, client_id: str) -> bool:
        client = self.client_repository.find_by_id(client_id)
        if not client:
            return False
        
        server = self.server_repository.find_by_id(client.server_id)
        if not server:
            return False
        
        if server.protocol == ProtocolType.WIREGUARD:
            self.wireguard_protocol.remove_client(server, client)
        elif server.protocol == ProtocolType.OPENVPN:
            # Remove client certificate
            pass
        
        return self.client_repository.delete(client_id)
    
    def get_traffic_stats(self, server_id: str) -> Dict[str, int]:
        server = self.server_repository.find_by_id(server_id)
        if not server:
            return {}
        
        if server.protocol == ProtocolType.WIREGUARD:
            return self.wireguard_protocol.get_traffic_stats(server)
        elif server.protocol == ProtocolType.OPENVPN:
            return self.openvpn_protocol.get_traffic_stats(server)
        else:
            return {}
    
    def update_client_bandwidth(self, client_id: str, bytes_used: int) -> bool:
        client = self.client_repository.find_by_id(client_id)
        if not client:
            return False
        
        client.update_bandwidth_usage(bytes_used)
        return self.client_repository.update(client)
    
    def get_active_clients(self, server_id: str) -> List[VPNClient]:
        return self.client_repository.find_by_server_id(server_id)
    
    def get_expired_clients(self) -> List[VPNClient]:
        return self.client_repository.find_expired_clients()
    
    def get_bandwidth_exceeded_clients(self) -> List[VPNClient]:
        return self.client_repository.find_by_bandwidth_exceeded() 