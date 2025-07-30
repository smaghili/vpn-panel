import asyncio
import json
import logging
from typing import Dict, Set, Any
from datetime import datetime
from fastapi import WebSocket, WebSocketDisconnect
from dataclasses import dataclass, asdict

@dataclass
class TrafficData:
    timestamp: datetime
    client_id: str
    rx_bytes: int
    tx_bytes: int
    connection_time: int
    endpoint: str

@dataclass
class ServerStatus:
    timestamp: datetime
    server_id: str
    status: str
    active_connections: int
    total_traffic: Dict[str, int]
    cpu_usage: float
    memory_usage: float

class WebSocketManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self.client_connections: Dict[str, Set[WebSocket]] = {}
        self.admin_connections: Set[WebSocket] = set()
        self.logger = logging.getLogger(__name__)
    
    async def connect(self, websocket: WebSocket, user_id: str, is_admin: bool = False):
        """Connect a new WebSocket client"""
        await websocket.accept()
        self.active_connections.add(websocket)
        
        if is_admin:
            self.admin_connections.add(websocket)
        else:
            if user_id not in self.client_connections:
                self.client_connections[user_id] = set()
            self.client_connections[user_id].add(websocket)
        
        self.logger.info(f"WebSocket connected: user_id={user_id}, is_admin={is_admin}")
    
    def disconnect(self, websocket: WebSocket, user_id: str, is_admin: bool = False):
        """Disconnect a WebSocket client"""
        self.active_connections.discard(websocket)
        
        if is_admin:
            self.admin_connections.discard(websocket)
        else:
            if user_id in self.client_connections:
                self.client_connections[user_id].discard(websocket)
                if not self.client_connections[user_id]:
                    del self.client_connections[user_id]
        
        self.logger.info(f"WebSocket disconnected: user_id={user_id}, is_admin={is_admin}")
    
    async def send_traffic_update(self, traffic_data: TrafficData):
        """Send traffic update to relevant clients"""
        message = {
            "type": "traffic_update",
            "data": asdict(traffic_data),
            "timestamp": datetime.now().isoformat()
        }
        
        # Send to admin connections
        await self._broadcast_to_connections(self.admin_connections, message)
        
        # Send to specific client connections
        if traffic_data.client_id in self.client_connections:
            await self._broadcast_to_connections(self.client_connections[traffic_data.client_id], message)
    
    async def send_server_status(self, server_status: ServerStatus):
        """Send server status update to admin connections"""
        message = {
            "type": "server_status",
            "data": asdict(server_status),
            "timestamp": datetime.now().isoformat()
        }
        
        await self._broadcast_to_connections(self.admin_connections, message)
    
    async def send_system_alert(self, alert_type: str, message: str, severity: str = "info"):
        """Send system alert to admin connections"""
        alert = {
            "type": "system_alert",
            "data": {
                "alert_type": alert_type,
                "message": message,
                "severity": severity,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        await self._broadcast_to_connections(self.admin_connections, alert)
    
    async def send_user_notification(self, user_id: str, notification_type: str, message: str):
        """Send notification to specific user"""
        notification = {
            "type": "notification",
            "data": {
                "notification_type": notification_type,
                "message": message,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        if user_id in self.client_connections:
            await self._broadcast_to_connections(self.client_connections[user_id], notification)
    
    async def _broadcast_to_connections(self, connections: Set[WebSocket], message: Dict[str, Any]):
        """Broadcast message to a set of connections"""
        if not connections:
            return
        
        message_json = json.dumps(message)
        disconnected = set()
        
        for connection in connections:
            try:
                await connection.send_text(message_json)
            except Exception as e:
                self.logger.error(f"Error sending message: {e}")
                disconnected.add(connection)
        
        # Remove disconnected connections
        for connection in disconnected:
            connections.discard(connection)
            self.active_connections.discard(connection)
    
    async def broadcast_to_all(self, message: Dict[str, Any]):
        """Broadcast message to all connected clients"""
        await self._broadcast_to_connections(self.active_connections, message)
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get WebSocket connection statistics"""
        return {
            "total_connections": len(self.active_connections),
            "admin_connections": len(self.admin_connections),
            "client_connections": len(self.client_connections),
            "connected_users": list(self.client_connections.keys())
        }

# Global WebSocket manager instance
websocket_manager = WebSocketManager() 