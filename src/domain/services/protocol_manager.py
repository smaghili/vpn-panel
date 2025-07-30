from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Type
from datetime import datetime
import logging

from ..entities.user_profile import ProtocolType, ProtocolProfile, WireGuardProfile, OpenVPNProfile, UserProfile, AuthType

class ProtocolHandler(ABC):
    """Abstract base class for protocol handlers"""
    
    @abstractmethod
    def create_profile(self, user_id: str, server_id: str, config: Dict[str, Any]) -> ProtocolProfile:
        """Create a protocol profile for user"""
        pass
    
    @abstractmethod
    def delete_profile(self, profile: ProtocolProfile) -> bool:
        """Delete a protocol profile"""
        pass
    
    @abstractmethod
    def update_profile(self, profile: ProtocolProfile, config: Dict[str, Any]) -> bool:
        """Update a protocol profile"""
        pass
    
    @abstractmethod
    def get_traffic_stats(self, profile: ProtocolProfile) -> Dict[str, int]:
        """Get traffic statistics for profile"""
        pass
    
    @abstractmethod
    def check_connection(self, profile: ProtocolProfile) -> bool:
        """Check if profile is connected"""
        pass
    
    @abstractmethod
    def generate_config(self, profile: ProtocolProfile) -> str:
        """Generate configuration file for profile"""
        pass

class WireGuardHandler(ProtocolHandler):
    """WireGuard protocol handler"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def create_profile(self, user_id: str, server_id: str, config: Dict[str, Any]) -> WireGuardProfile:
        """Create WireGuard profile"""
        from ...infrastructure.protocols.wireguard import WireGuardProtocol
        
        wg_protocol = WireGuardProtocol()
        private_key, public_key = wg_protocol.generate_keypair()
        
        profile = WireGuardProfile(
            user_id=user_id,
            server_id=server_id,
            public_key=public_key,
            private_key=private_key,
            allowed_ips=config.get("allowed_ips", "10.0.0.2/32"),
            endpoint=config.get("endpoint", ""),
            daily_limit_bytes=config.get("daily_limit_gb", 0) * (1024**3),
            monthly_limit_bytes=config.get("monthly_limit_gb", 0) * (1024**3)
        )
        
        # Add to WireGuard server
        wg_protocol.add_client_to_server(server_id, profile)
        
        return profile
    
    def delete_profile(self, profile: WireGuardProfile) -> bool:
        """Delete WireGuard profile"""
        from ...infrastructure.protocols.wireguard import WireGuardProtocol
        
        wg_protocol = WireGuardProtocol()
        return wg_protocol.remove_client_from_server(profile.server_id, profile.public_key)
    
    def update_profile(self, profile: WireGuardProfile, config: Dict[str, Any]) -> bool:
        """Update WireGuard profile"""
        if "allowed_ips" in config:
            profile.allowed_ips = config["allowed_ips"]
        if "daily_limit_gb" in config:
            profile.daily_limit_bytes = config["daily_limit_gb"] * (1024**3)
        if "monthly_limit_gb" in config:
            profile.monthly_limit_bytes = config["monthly_limit_gb"] * (1024**3)
        
        profile.updated_at = datetime.now()
        return True
    
    def get_traffic_stats(self, profile: WireGuardProfile) -> Dict[str, int]:
        """Get WireGuard traffic statistics"""
        from ...infrastructure.protocols.wireguard import WireGuardProtocol
        
        wg_protocol = WireGuardProtocol()
        return wg_protocol.get_client_traffic_stats(profile.public_key)
    
    def check_connection(self, profile: WireGuardProfile) -> bool:
        """Check if WireGuard client is connected"""
        from ...infrastructure.protocols.wireguard import WireGuardProtocol
        
        wg_protocol = WireGuardProtocol()
        return wg_protocol.is_client_connected(profile.public_key)
    
    def generate_config(self, profile: WireGuardProfile) -> str:
        """Generate WireGuard configuration file"""
        config = f"""[Interface]
PrivateKey = {profile.private_key}
Address = {profile.allowed_ips}
DNS = 8.8.8.8, 8.8.4.4

[Peer]
PublicKey = SERVER_PUBLIC_KEY
Endpoint = {profile.endpoint}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
        return config

class OpenVPNHandler(ProtocolHandler):
    """OpenVPN protocol handler"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def create_profile(self, user_id: str, server_id: str, config: Dict[str, Any]) -> OpenVPNProfile:
        """Create OpenVPN profile"""
        from ...infrastructure.protocols.openvpn_auth import openvpn_auth_manager
        
        auth_type = AuthType(config.get("auth_type", "certificate_only"))
        
        profile = OpenVPNProfile(
            user_id=user_id,
            server_id=server_id,
            auth_type=auth_type,
            daily_limit_bytes=config.get("daily_limit_gb", 0) * (1024**3),
            monthly_limit_bytes=config.get("monthly_limit_gb", 0) * (1024**3)
        )
        
        if auth_type == AuthType.USERNAME_PASSWORD:
            username = config.get("username", f"user_{user_id}")
            password = config.get("password", "")
            
            profile.username = username
            profile.password_hash = self._hash_password(password)
            
            # Add to OpenVPN auth system
            openvpn_auth_manager.create_user(
                username=username,
                password=password,
                client_id=user_id,
                server_id=server_id,
                bandwidth_limit=config.get("bandwidth_limit_mbps", 0),
                daily_limit=config.get("daily_limit_gb", 0)
            )
        else:
            # Certificate-based auth
            from ...infrastructure.protocols.openvpn import OpenVPNProtocol
            ovpn_protocol = OpenVPNProtocol()
            cert_path, key_path = ovpn_protocol.generate_client_cert(user_id, server_id)
            profile.certificate_path = cert_path
            profile.key_path = key_path
        
        return profile
    
    def delete_profile(self, profile: OpenVPNProfile) -> bool:
        """Delete OpenVPN profile"""
        if profile.auth_type == AuthType.USERNAME_PASSWORD and profile.username:
            from ...infrastructure.protocols.openvpn_auth import openvpn_auth_manager
            return openvpn_auth_manager.delete_user(profile.username)
        return True
    
    def update_profile(self, profile: OpenVPNProfile, config: Dict[str, Any]) -> bool:
        """Update OpenVPN profile"""
        if "daily_limit_gb" in config:
            profile.daily_limit_bytes = config["daily_limit_gb"] * (1024**3)
        if "monthly_limit_gb" in config:
            profile.monthly_limit_bytes = config["monthly_limit_gb"] * (1024**3)
        
        profile.updated_at = datetime.now()
        return True
    
    def get_traffic_stats(self, profile: OpenVPNProfile) -> Dict[str, int]:
        """Get OpenVPN traffic statistics"""
        from ...infrastructure.protocols.openvpn import OpenVPNProtocol
        
        ovpn_protocol = OpenVPNProtocol()
        return ovpn_protocol.get_client_traffic_stats(profile.user_id)
    
    def check_connection(self, profile: OpenVPNProfile) -> bool:
        """Check if OpenVPN client is connected"""
        from ...infrastructure.protocols.openvpn import OpenVPNProtocol
        
        ovpn_protocol = OpenVPNProtocol()
        return ovpn_protocol.is_client_connected(profile.user_id)
    
    def generate_config(self, profile: OpenVPNProfile) -> str:
        """Generate OpenVPN configuration file"""
        if profile.auth_type == AuthType.CERTIFICATE_ONLY:
            config = f"""client
dev tun
proto udp
remote SERVER_IP SERVER_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert {profile.certificate_path}
key {profile.key_path}
remote-cert-tls server
cipher AES-256-CBC
auth SHA256
verb 3
"""
        else:
            config = f"""client
dev tun
proto udp
remote SERVER_IP SERVER_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
auth-user-pass auth.txt
remote-cert-tls server
cipher AES-256-CBC
auth SHA256
verb 3
"""
        return config
    
    def _hash_password(self, password: str) -> str:
        """Hash password for storage"""
        import hashlib
        return hashlib.sha256(password.encode()).hexdigest()

class ProtocolManager:
    """Manager for handling multiple protocols"""
    
    def __init__(self):
        self.handlers: Dict[ProtocolType, ProtocolHandler] = {
            ProtocolType.WIREGUARD: WireGuardHandler(),
            ProtocolType.OPENVPN: OpenVPNHandler(),
        }
        self.logger = logging.getLogger(__name__)
    
    def register_handler(self, protocol: ProtocolType, handler: ProtocolHandler):
        """Register a new protocol handler"""
        self.handlers[protocol] = handler
        self.logger.info(f"Registered handler for protocol: {protocol.value}")
    
    def get_handler(self, protocol: ProtocolType) -> Optional[ProtocolHandler]:
        """Get handler for specific protocol"""
        return self.handlers.get(protocol)
    
    def create_user_profile(self, user_id: str, username: str, email: str, 
                           password_hash: str, protocol_configs: Dict[str, Any]) -> UserProfile:
        """Create unified user profile with multiple protocols"""
        
        user_profile = UserProfile(
            user_id=user_id,
            username=username,
            email=email,
            password_hash=password_hash,
            total_daily_limit_bytes=protocol_configs.get("total_daily_limit_gb", 0) * (1024**3),
            total_monthly_limit_bytes=protocol_configs.get("total_monthly_limit_gb", 0) * (1024**3)
        )
        
        # Create profiles for each enabled protocol
        for protocol_name, config in protocol_configs.get("protocols", {}).items():
            if config.get("enabled", False):
                protocol = ProtocolType(protocol_name)
                handler = self.get_handler(protocol)
                
                if handler:
                    profile = handler.create_profile(
                        user_id=user_id,
                        server_id=config.get("server_id"),
                        config=config
                    )
                    user_profile.add_protocol_profile(profile)
                else:
                    self.logger.error(f"No handler found for protocol: {protocol_name}")
        
        return user_profile
    
    def delete_user_profiles(self, user_profile: UserProfile) -> bool:
        """Delete all protocol profiles for user"""
        success = True
        
        for protocol, profile in user_profile.protocols.items():
            handler = self.get_handler(protocol)
            if handler:
                if not handler.delete_profile(profile):
                    success = False
                    self.logger.error(f"Failed to delete {protocol.value} profile for user {user_profile.user_id}")
        
        return success
    
    def update_user_profiles(self, user_profile: UserProfile, 
                           protocol_configs: Dict[str, Any]) -> bool:
        """Update protocol profiles for user"""
        success = True
        
        for protocol_name, config in protocol_configs.get("protocols", {}).items():
            protocol = ProtocolType(protocol_name)
            profile = user_profile.get_protocol_profile(protocol)
            handler = self.get_handler(protocol)
            
            if profile and handler:
                if not handler.update_profile(profile, config):
                    success = False
                    self.logger.error(f"Failed to update {protocol.value} profile for user {user_profile.user_id}")
        
        return success
    
    def get_user_traffic_stats(self, user_profile: UserProfile) -> Dict[str, Any]:
        """Get traffic statistics for all user protocols"""
        stats = {}
        
        for protocol, profile in user_profile.protocols.items():
            handler = self.get_handler(protocol)
            if handler:
                stats[protocol.value] = handler.get_traffic_stats(profile)
        
        return stats
    
    def check_user_connections(self, user_profile: UserProfile) -> Dict[str, bool]:
        """Check connection status for all user protocols"""
        connections = {}
        
        for protocol, profile in user_profile.protocols.items():
            handler = self.get_handler(protocol)
            if handler:
                connections[protocol.value] = handler.check_connection(profile)
        
        return connections
    
    def generate_user_configs(self, user_profile: UserProfile) -> Dict[str, str]:
        """Generate configuration files for all user protocols"""
        configs = {}
        
        for protocol, profile in user_profile.protocols.items():
            handler = self.get_handler(protocol)
            if handler:
                configs[protocol.value] = handler.generate_config(profile)
        
        return configs

# Global protocol manager instance
protocol_manager = ProtocolManager() 