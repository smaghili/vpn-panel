from datetime import datetime
from enum import Enum
from dataclasses import dataclass
from typing import Optional
import secrets
import subprocess
import os

class ProtocolType(Enum):
    WIREGUARD = "wireguard"
    OPENVPN = "openvpn"

class ServerStatus(Enum):
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"
    STARTING = "starting"
    STOPPING = "stopping"

@dataclass
class VPNServer:
    id: str
    name: str
    protocol: ProtocolType
    port: int
    interface: str
    private_key: str
    public_key: str
    status: ServerStatus
    config_path: str
    created_at: datetime
    updated_at: datetime
    
    def start(self) -> bool:
        try:
            if self.protocol == ProtocolType.WIREGUARD:
                subprocess.run(["wg-quick", "up", self.interface], check=True)
            elif self.protocol == ProtocolType.OPENVPN:
                subprocess.run(["systemctl", "start", f"openvpn@{self.name}"], check=True)
            self.status = ServerStatus.RUNNING
            self.updated_at = datetime.now()
            return True
        except subprocess.CalledProcessError:
            self.status = ServerStatus.ERROR
            return False
    
    def stop(self) -> bool:
        try:
            if self.protocol == ProtocolType.WIREGUARD:
                subprocess.run(["wg-quick", "down", self.interface], check=True)
            elif self.protocol == ProtocolType.OPENVPN:
                subprocess.run(["systemctl", "stop", f"openvpn@{self.name}"], check=True)
            self.status = ServerStatus.STOPPED
            self.updated_at = datetime.now()
            return True
        except subprocess.CalledProcessError:
            self.status = ServerStatus.ERROR
            return False
    
    def restart(self) -> bool:
        return self.stop() and self.start()
    
    def is_running(self) -> bool:
        try:
            if self.protocol == ProtocolType.WIREGUARD:
                result = subprocess.run(["wg", "show", self.interface], capture_output=True)
                return result.returncode == 0
            elif self.protocol == ProtocolType.OPENVPN:
                result = subprocess.run(["systemctl", "is-active", f"openvpn@{self.name}"], capture_output=True)
                return result.stdout.decode().strip() == "active"
        except:
            pass
        return False
    
    def get_status(self) -> ServerStatus:
        if self.is_running():
            return ServerStatus.RUNNING
        return ServerStatus.STOPPED
    
    def update_config(self):
        self.updated_at = datetime.now()
    
    def generate_keys(self):
        if self.protocol == ProtocolType.WIREGUARD:
            private_key = subprocess.run(["wg", "genkey"], capture_output=True, text=True).stdout.strip()
            public_key = subprocess.run(["wg", "pubkey"], input=private_key, capture_output=True, text=True).stdout.strip()
            self.private_key = private_key
            self.public_key = public_key
        elif self.protocol == ProtocolType.OPENVPN:
            self.private_key = secrets.token_hex(32)
            self.public_key = secrets.token_hex(32) 