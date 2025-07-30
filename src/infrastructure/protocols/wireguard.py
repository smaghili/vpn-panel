import subprocess
import os
import tempfile
import json
import re
from typing import Optional, Dict, Any, List
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.backends import default_backend
from ...domain.entities.vpn_server import VPNServer
from ...domain.entities.vpn_client import VPNClient

class WireGuardProtocol:
    def __init__(self, config_dir: str = "/etc/wireguard"):
        self.config_dir = config_dir
        self._ensure_config_dir()
    
    def _ensure_config_dir(self):
        """Ensure configuration directory exists with proper permissions"""
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir, mode=0o700)
    
    def generate_keypair(self) -> tuple[str, str]:
        """Generate WireGuard private/public key pair"""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Convert to base64
        import base64
        private_b64 = base64.b64encode(private_bytes).decode('utf-8')
        public_b64 = base64.b64encode(public_bytes).decode('utf-8')
        
        return private_b64, public_b64
    
    def create_server(self, server: VPNServer) -> bool:
        """Create WireGuard server configuration"""
        try:
            # Generate keys if not provided
            if not server.private_key:
                private_key, public_key = self.generate_keypair()
                server.private_key = private_key
                server.public_key = public_key
            
            config_content = self._generate_server_config(server)
            config_path = os.path.join(self.config_dir, f"{server.interface}.conf")
            
            with open(config_path, 'w') as f:
                f.write(config_content)
            os.chmod(config_path, 0o600)
            server.config_path = config_path
            
            return True
        except Exception as e:
            print(f"Error creating WireGuard server: {e}")
            return False
    
    def _generate_server_config(self, server: VPNServer) -> str:
        """Generate WireGuard server configuration"""
        config = f"""[Interface]
PrivateKey = {server.private_key}
Address = 10.0.0.1/24
ListenPort = {server.port}
SaveConfig = true
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

"""
        return config
    
    def add_client(self, server: VPNServer, client: VPNClient) -> bool:
        """Add client to WireGuard server"""
        config_path = server.config_path
        if not os.path.exists(config_path):
            return False
        
        # Generate client keys if not provided
        if not client.private_key:
            private_key, public_key = self.generate_keypair()
            client.private_key = private_key
            client.public_key = public_key
        
        peer_config = f"""
[Peer]
PublicKey = {client.public_key}
AllowedIPs = {client.allowed_ips}
"""
        
        try:
            with open(config_path, 'a') as f:
                f.write(peer_config)
            return True
        except Exception as e:
            print(f"Error adding client: {e}")
            return False
    
    def remove_client(self, server: VPNServer, client: VPNClient) -> bool:
        """Remove client from WireGuard server"""
        config_path = server.config_path
        if not os.path.exists(config_path):
            return False
        
        try:
            with open(config_path, 'r') as f:
                lines = f.readlines()
            
            new_lines = []
            skip_peer = False
            
            for line in lines:
                if line.strip() == f"PublicKey = {client.public_key}":
                    skip_peer = True
                    continue
                if skip_peer and line.strip().startswith("[Peer]"):
                    skip_peer = False
                if not skip_peer:
                    new_lines.append(line)
            
            with open(config_path, 'w') as f:
                f.writelines(new_lines)
            return True
        except Exception as e:
            print(f"Error removing client: {e}")
            return False
    
    def start_server(self, server: VPNServer) -> bool:
        """Start WireGuard server"""
        try:
            result = subprocess.run(
                ["wg-quick", "up", server.interface], 
                capture_output=True, 
                text=True,
                check=True
            )
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error starting WireGuard server: {e.stderr}")
            return False
    
    def stop_server(self, server: VPNServer) -> bool:
        """Stop WireGuard server"""
        try:
            result = subprocess.run(
                ["wg-quick", "down", server.interface], 
                capture_output=True, 
                text=True,
                check=True
            )
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error stopping WireGuard server: {e.stderr}")
            return False
    
    def get_server_status(self, server: VPNServer) -> Dict[str, Any]:
        """Get WireGuard server status"""
        try:
            result = subprocess.run(
                ["wg", "show", server.interface], 
                capture_output=True, 
                text=True,
                check=True
            )
            return self._parse_wg_output(result.stdout)
        except subprocess.CalledProcessError:
            return {"status": "stopped", "peers": []}
    
    def _parse_wg_output(self, output: str) -> Dict[str, Any]:
        """Parse wg show output"""
        lines = output.strip().split('\n')
        status = {"status": "running", "peers": []}
        
        current_peer = None
        
        for line in lines:
            line = line.strip()
            if line.startswith('peer:'):
                if current_peer:
                    status["peers"].append(current_peer)
                current_peer = {"public_key": line.split(':')[1].strip()}
            elif line.startswith('endpoint:') and current_peer:
                current_peer["endpoint"] = line.split(':')[1].strip()
            elif line.startswith('allowed ips:') and current_peer:
                current_peer["allowed_ips"] = line.split(':')[1].strip()
            elif line.startswith('latest handshake:') and current_peer:
                current_peer["latest_handshake"] = line.split(':')[1].strip()
            elif line.startswith('transfer:') and current_peer:
                transfer = line.split(':')[1].strip()
                rx, tx = transfer.split(',')
                current_peer["rx_bytes"] = self._parse_bytes(rx.strip())
                current_peer["tx_bytes"] = self._parse_bytes(tx.strip())
        
        if current_peer:
            status["peers"].append(current_peer)
        
        return status
    
    def generate_client_config(self, client: VPNClient, server: VPNServer, server_public_ip: str) -> str:
        """Generate WireGuard client configuration"""
        config = f"""[Interface]
PrivateKey = {client.private_key}
Address = {client.allowed_ips}
DNS = 8.8.8.8, 8.8.4.4

[Peer]
PublicKey = {server.public_key}
Endpoint = {server_public_ip}:{server.port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
        return config
    
    def get_traffic_stats(self, server: VPNServer) -> Dict[str, int]:
        """Get traffic statistics for all clients"""
        try:
            result = subprocess.run(
                ["wg", "show", server.interface], 
                capture_output=True, 
                text=True,
                check=True
            )
            return self._parse_traffic_stats(result.stdout)
        except subprocess.CalledProcessError:
            return {}
    
    def _parse_traffic_stats(self, output: str) -> Dict[str, int]:
        """Parse traffic statistics from wg show output"""
        stats = {}
        lines = output.strip().split('\n')
        
        current_peer = None
        
        for line in lines:
            line = line.strip()
            if line.startswith('peer:'):
                current_peer = line.split(':')[1].strip()
            elif line.startswith('transfer:') and current_peer:
                transfer = line.split(':')[1].strip()
                rx, tx = transfer.split(',')
                stats[current_peer] = {
                    "rx_bytes": self._parse_bytes(rx.strip()),
                    "tx_bytes": self._parse_bytes(tx.strip())
                }
        
        return stats
    
    def _parse_bytes(self, size_str: str) -> int:
        """Parse byte size string to integer"""
        size_str = size_str.strip()
        if 'B' in size_str:
            return int(size_str.replace('B', ''))
        elif 'KB' in size_str:
            return int(float(size_str.replace('KB', '')) * 1024)
        elif 'MB' in size_str:
            return int(float(size_str.replace('MB', '')) * 1024 * 1024)
        elif 'GB' in size_str:
            return int(float(size_str.replace('GB', '')) * 1024 * 1024 * 1024)
        else:
            return int(size_str)
    
    def set_bandwidth_limit(self, client: VPNClient, limit_mbps: int) -> bool:
        """Set bandwidth limit for client using tc"""
        try:
            # Create tc qdisc and class for bandwidth limiting
            interface = "wg0"  # Default WireGuard interface
            
            # Add qdisc if not exists
            subprocess.run([
                "tc", "qdisc", "add", "dev", interface, 
                "root", "handle", "1:", "htb", "default", "30"
            ], capture_output=True)
            
            # Add class for this client
            class_id = f"1:{hash(client.public_key) % 1000}"
            subprocess.run([
                "tc", "class", "add", "dev", interface, 
                "parent", "1:", "classid", class_id, 
                "htb", "rate", f"{limit_mbps}mbit"
            ], capture_output=True)
            
            # Add filter to match client IP
            subprocess.run([
                "tc", "filter", "add", "dev", interface, 
                "protocol", "ip", "parent", "1:", 
                "prio", "1", "u32", 
                "match", "ip", "dst", client.allowed_ips, 
                "flowid", class_id
            ], capture_output=True)
            
            return True
        except Exception as e:
            print(f"Error setting bandwidth limit: {e}")
            return False 