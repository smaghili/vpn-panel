import subprocess
import os
import tempfile
from typing import Optional, Dict, Any
from ...domain.entities.vpn_server import VPNServer
from ...domain.entities.vpn_client import VPNClient

class OpenVPNProtocol:
    def __init__(self, config_dir: str = "/etc/openvpn"):
        self.config_dir = config_dir
        self._ensure_config_dir()
    
    def _ensure_config_dir(self):
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir, mode=0o700)
    
    def create_server(self, server: VPNServer) -> bool:
        config_content = self._generate_server_config(server)
        config_path = os.path.join(self.config_dir, f"{server.name}.conf")
        
        try:
            with open(config_path, 'w') as f:
                f.write(config_content)
            os.chmod(config_path, 0o600)
            server.config_path = config_path
            return True
        except Exception:
            return False
    
    def _generate_server_config(self, server: VPNServer) -> str:
        config = f"""port {server.port}
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
keepalive 10 120
tls-auth ta.key 0
cipher AES-256-CBC
auth SHA256
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3
explicit-exit-notify 1
"""
        return config
    
    def generate_certificates(self, server: VPNServer) -> bool:
        try:
            ca_dir = os.path.join(self.config_dir, "easy-rsa")
            if not os.path.exists(ca_dir):
                self._setup_easy_rsa()
            
            self._generate_ca()
            self._generate_server_cert(server.name)
            return True
        except Exception:
            return False
    
    def _setup_easy_rsa(self):
        easy_rsa_url = "https://github.com/OpenVPN/easy-rsa/archive/refs/tags/v3.1.7.tar.gz"
        subprocess.run(["wget", easy_rsa_url, "-O", "/tmp/easy-rsa.tar.gz"])
        subprocess.run(["tar", "-xzf", "/tmp/easy-rsa.tar.gz", "-C", "/tmp"])
        subprocess.run(["mv", "/tmp/easy-rsa-3.1.7", os.path.join(self.config_dir, "easy-rsa")])
    
    def _generate_ca(self):
        easy_rsa_dir = os.path.join(self.config_dir, "easy-rsa")
        subprocess.run(["./easyrsa", "init-pki"], cwd=easy_rsa_dir)
        subprocess.run(["./easyrsa", "build-ca", "nopass"], cwd=easy_rsa_dir, input=b"\n")
    
    def _generate_server_cert(self, server_name: str):
        easy_rsa_dir = os.path.join(self.config_dir, "easy-rsa")
        subprocess.run(["./easyrsa", "build-server-full", server_name, "nopass"], cwd=easy_rsa_dir)
        subprocess.run(["./easyrsa", "gen-dh"], cwd=easy_rsa_dir)
        subprocess.run(["openvpn", "--genkey", "secret", "ta.key"], cwd=self.config_dir)
    
    def generate_client_cert(self, client: VPNClient, server: VPNServer) -> bool:
        try:
            easy_rsa_dir = os.path.join(self.config_dir, "easy-rsa")
            subprocess.run(["./easyrsa", "build-client-full", client.name, "nopass"], cwd=easy_rsa_dir)
            return True
        except Exception:
            return False
    
    def start_server(self, server: VPNServer) -> bool:
        try:
            subprocess.run(["systemctl", "start", f"openvpn@{server.name}"], check=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def stop_server(self, server: VPNServer) -> bool:
        try:
            subprocess.run(["systemctl", "stop", f"openvpn@{server.name}"], check=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def get_server_status(self, server: VPNServer) -> Dict[str, Any]:
        try:
            result = subprocess.run(["systemctl", "is-active", f"openvpn@{server.name}"], 
                                  capture_output=True, text=True, check=True)
            status = result.stdout.strip()
            
            if status == "active":
                return self._get_connection_details(server)
            else:
                return {"status": "stopped", "clients": []}
        except subprocess.CalledProcessError:
            return {"status": "error", "clients": []}
    
    def _get_connection_details(self, server: VPNServer) -> Dict[str, Any]:
        status_file = os.path.join(self.config_dir, "openvpn-status.log")
        if not os.path.exists(status_file):
            return {"status": "running", "clients": []}
        
        try:
            with open(status_file, 'r') as f:
                content = f.read()
            return self._parse_status_file(content)
        except Exception:
            return {"status": "running", "clients": []}
    
    def _parse_status_file(self, content: str) -> Dict[str, Any]:
        lines = content.strip().split('\n')
        clients = []
        in_clients_section = False
        
        for line in lines:
            if line.startswith("OpenVPN CLIENT LIST"):
                in_clients_section = True
                continue
            elif line.startswith("ROUTING TABLE"):
                break
            elif in_clients_section and line.strip() and not line.startswith("Common Name"):
                parts = line.split(',')
                if len(parts) >= 4:
                    client = {
                        'name': parts[0],
                        'address': parts[1],
                        'bytes_received': parts[2],
                        'bytes_sent': parts[3],
                        'connected_since': parts[4] if len(parts) > 4 else ''
                    }
                    clients.append(client)
        
        return {"status": "running", "clients": clients}
    
    def generate_client_config(self, client: VPNClient, server: VPNServer, server_public_ip: str) -> str:
        config = f"""client
dev tun
proto udp
remote {server_public_ip} {server.port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
auth SHA256
comp-lzo
verb 3

<ca>
{self._get_ca_cert()}
</ca>

<cert>
{self._get_client_cert(client.name)}
</cert>

<key>
{self._get_client_key(client.name)}
</key>

<tls-auth>
{self._get_tls_auth()}
</tls-auth>
"""
        return config
    
    def _get_ca_cert(self) -> str:
        ca_path = os.path.join(self.config_dir, "easy-rsa", "pki", "ca.crt")
        try:
            with open(ca_path, 'r') as f:
                return f.read()
        except:
            return ""
    
    def _get_client_cert(self, client_name: str) -> str:
        cert_path = os.path.join(self.config_dir, "easy-rsa", "pki", "issued", f"{client_name}.crt")
        try:
            with open(cert_path, 'r') as f:
                return f.read()
        except:
            return ""
    
    def _get_client_key(self, client_name: str) -> str:
        key_path = os.path.join(self.config_dir, "easy-rsa", "pki", "private", f"{client_name}.key")
        try:
            with open(key_path, 'r') as f:
                return f.read()
        except:
            return ""
    
    def _get_tls_auth(self) -> str:
        ta_path = os.path.join(self.config_dir, "ta.key")
        try:
            with open(ta_path, 'r') as f:
                return f.read()
        except:
            return ""
    
    def get_traffic_stats(self, server: VPNServer) -> Dict[str, int]:
        status_file = os.path.join(self.config_dir, "openvpn-status.log")
        if not os.path.exists(status_file):
            return {}
        
        try:
            with open(status_file, 'r') as f:
                content = f.read()
            return self._parse_traffic_stats(content)
        except Exception:
            return {}
    
    def _parse_traffic_stats(self, content: str) -> Dict[str, int]:
        lines = content.strip().split('\n')
        total_received = 0
        total_sent = 0
        
        for line in lines:
            if ',' in line and not line.startswith("Common Name"):
                parts = line.split(',')
                if len(parts) >= 4:
                    try:
                        total_received += int(parts[2])
                        total_sent += int(parts[3])
                    except ValueError:
                        continue
        
        return {"received": total_received, "sent": total_sent} 