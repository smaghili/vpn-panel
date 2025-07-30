from datetime import datetime
from enum import Enum
from dataclasses import dataclass
from typing import Optional
import secrets

class ClientStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    EXPIRED = "expired"
    SUSPENDED = "suspended"

@dataclass
class VPNClient:
    id: str
    user_id: str
    server_id: str
    name: str
    public_key: str
    private_key: str
    allowed_ips: str
    bandwidth_limit: int
    bandwidth_used: int
    expire_date: Optional[datetime]
    status: ClientStatus
    created_at: datetime
    updated_at: datetime
    last_connected: Optional[datetime] = None
    
    def is_active(self) -> bool:
        return self.status == ClientStatus.ACTIVE
    
    def has_expired(self) -> bool:
        if not self.expire_date:
            return False
        return datetime.now() > self.expire_date
    
    def is_bandwidth_exceeded(self) -> bool:
        return self.bandwidth_used >= self.bandwidth_limit
    
    def update_bandwidth_usage(self, bytes_used: int):
        self.bandwidth_used += bytes_used
        self.updated_at = datetime.now()
    
    def reset_bandwidth_usage(self):
        self.bandwidth_used = 0
        self.updated_at = datetime.now()
    
    def update_last_connection(self):
        self.last_connected = datetime.now()
        self.updated_at = datetime.now()
    
    def suspend(self):
        self.status = ClientStatus.SUSPENDED
        self.updated_at = datetime.now()
    
    def activate(self):
        self.status = ClientStatus.ACTIVE
        self.updated_at = datetime.now()
    
    def generate_keys(self):
        if self.public_key and self.private_key:
            return
        
        private_key = secrets.token_hex(32)
        public_key = secrets.token_hex(32)
        self.private_key = private_key
        self.public_key = public_key 