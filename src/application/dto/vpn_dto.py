from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class ServerCreateRequest(BaseModel):
    name: str
    protocol: str
    port: int
    interface: Optional[str] = None

class ServerResponse(BaseModel):
    id: str
    name: str
    protocol: str
    port: int
    interface: str
    status: str
    created_at: datetime

class ServerStatusResponse(BaseModel):
    status: str
    peers: Optional[List[dict]] = None
    clients: Optional[List[dict]] = None

class ClientCreateRequest(BaseModel):
    user_id: str
    server_id: str
    name: str
    bandwidth_limit: int
    expire_date: Optional[datetime] = None

class ClientResponse(BaseModel):
    id: str
    user_id: str
    server_id: str
    name: str
    allowed_ips: str
    bandwidth_limit: int
    bandwidth_used: int
    status: str
    created_at: datetime
    last_connected: Optional[datetime] = None
    expire_date: Optional[datetime] = None

class TrafficStatsResponse(BaseModel):
    received: int
    sent: int
    total: int

class DashboardStatsResponse(BaseModel):
    total_servers: int
    total_clients: int
    total_users: int
    active_connections: int
    recent_servers: List[ServerResponse] 