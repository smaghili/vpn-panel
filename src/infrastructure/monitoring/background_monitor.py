import asyncio
import time
import psutil
import logging
from typing import Dict, Any
from datetime import datetime
from dataclasses import asdict

from .websocket_manager import websocket_manager, TrafficData, ServerStatus
from .performance_monitor import performance_monitor
from ..traffic.bandwidth_manager import bandwidth_manager
from ..analytics.traffic_analytics import traffic_analytics, TrafficRecord

class BackgroundMonitor:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.running = False
        self.monitoring_interval = 5  # seconds
        
    async def start_monitoring(self):
        """Start background monitoring"""
        self.running = True
        self.logger.info("Starting background monitoring service")
        
        while self.running:
            try:
                await self._collect_and_broadcast_data()
                await asyncio.sleep(self.monitoring_interval)
            except Exception as e:
                self.logger.error(f"Error in background monitoring: {e}")
                await asyncio.sleep(self.monitoring_interval)
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        self.running = False
        self.logger.info("Stopping background monitoring service")
    
    async def _collect_and_broadcast_data(self):
        """Collect system data and broadcast via WebSocket"""
        try:
            # Collect system metrics
            system_metrics = self._collect_system_metrics()
            
            # Collect VPN traffic data
            vpn_traffic = await self._collect_vpn_traffic()
            
            # Collect server status
            server_status = await self._collect_server_status()
            
            # Broadcast to WebSocket clients
            await self._broadcast_updates(system_metrics, vpn_traffic, server_status)
            
            # Record analytics data
            await self._record_analytics(vpn_traffic)
            
        except Exception as e:
            self.logger.error(f"Error collecting and broadcasting data: {e}")
    
    def _collect_system_metrics(self) -> Dict[str, Any]:
        """Collect system performance metrics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network = psutil.net_io_counters()
            
            return {
                "cpu_usage": cpu_percent,
                "memory_usage": memory.percent,
                "memory_available": memory.available,
                "disk_usage": disk.percent,
                "disk_free": disk.free,
                "network_rx": network.bytes_recv,
                "network_tx": network.bytes_sent,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error collecting system metrics: {e}")
            return {}
    
    async def _collect_vpn_traffic(self) -> Dict[str, Any]:
        """Collect VPN traffic data"""
        try:
            # Get WireGuard traffic
            wg_traffic = self._get_wireguard_traffic()
            
            # Get OpenVPN traffic
            ovpn_traffic = self._get_openvpn_traffic()
            
            # Combine traffic data
            total_traffic = {
                "wireguard": wg_traffic,
                "openvpn": ovpn_traffic,
                "total_rx": wg_traffic.get("total_rx", 0) + ovpn_traffic.get("total_rx", 0),
                "total_tx": wg_traffic.get("total_tx", 0) + ovpn_traffic.get("total_tx", 0),
                "active_connections": wg_traffic.get("active_connections", 0) + ovpn_traffic.get("active_connections", 0),
                "timestamp": datetime.now().isoformat()
            }
            
            return total_traffic
            
        except Exception as e:
            self.logger.error(f"Error collecting VPN traffic: {e}")
            return {}
    
    def _get_wireguard_traffic(self) -> Dict[str, Any]:
        """Get WireGuard traffic statistics"""
        try:
            import subprocess
            
            # Run wg show to get traffic stats
            result = subprocess.run(
                ["wg", "show", "wg0", "dump"],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                return {"total_rx": 0, "total_tx": 0, "active_connections": 0}
            
            lines = result.stdout.strip().split('\n')
            total_rx = 0
            total_tx = 0
            active_connections = 0
            
            for line in lines[1:]:  # Skip header line
                parts = line.split('\t')
                if len(parts) >= 8:
                    rx_bytes = int(parts[6]) if parts[6] else 0
                    tx_bytes = int(parts[7]) if parts[7] else 0
                    total_rx += rx_bytes
                    total_tx += tx_bytes
                    
                    # Check if connection is active (has recent handshake)
                    if len(parts) > 8 and parts[8]:
                        active_connections += 1
            
            return {
                "total_rx": total_rx,
                "total_tx": total_tx,
                "active_connections": active_connections
            }
            
        except Exception as e:
            self.logger.error(f"Error getting WireGuard traffic: {e}")
            return {"total_rx": 0, "total_tx": 0, "active_connections": 0}
    
    def _get_openvpn_traffic(self) -> Dict[str, Any]:
        """Get OpenVPN traffic statistics"""
        try:
            import subprocess
            import os
            
            # Check OpenVPN status file
            status_file = "/var/log/openvpn/status.log"
            if not os.path.exists(status_file):
                return {"total_rx": 0, "total_tx": 0, "active_connections": 0}
            
            with open(status_file, 'r') as f:
                content = f.read()
            
            # Parse OpenVPN status
            total_rx = 0
            total_tx = 0
            active_connections = 0
            
            lines = content.split('\n')
            in_client_list = False
            
            for line in lines:
                if line.strip() == "OpenVPN CLIENT LIST":
                    in_client_list = True
                    continue
                elif line.strip() == "ROUTING TABLE":
                    break
                elif in_client_list and line.strip() and not line.startswith("Common Name"):
                    parts = line.split(',')
                    if len(parts) >= 4:
                        try:
                            rx_bytes = int(parts[2]) if parts[2] else 0
                            tx_bytes = int(parts[3]) if parts[3] else 0
                            total_rx += rx_bytes
                            total_tx += tx_bytes
                            active_connections += 1
                        except ValueError:
                            continue
            
            return {
                "total_rx": total_rx,
                "total_tx": total_tx,
                "active_connections": active_connections
            }
            
        except Exception as e:
            self.logger.error(f"Error getting OpenVPN traffic: {e}")
            return {"total_rx": 0, "total_tx": 0, "active_connections": 0}
    
    async def _collect_server_status(self) -> Dict[str, Any]:
        """Collect VPN server status"""
        try:
            import subprocess
            
            servers_status = {}
            
            # Check WireGuard server
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", "wg-quick@wg0"],
                    capture_output=True,
                    text=True
                )
                wg_status = "running" if result.stdout.strip() == "active" else "stopped"
                servers_status["wireguard"] = {
                    "status": wg_status,
                    "interface": "wg0"
                }
            except Exception as e:
                self.logger.error(f"Error checking WireGuard status: {e}")
                servers_status["wireguard"] = {"status": "unknown", "interface": "wg0"}
            
            # Check OpenVPN server
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", "openvpn@server"],
                    capture_output=True,
                    text=True
                )
                ovpn_status = "running" if result.stdout.strip() == "active" else "stopped"
                servers_status["openvpn"] = {
                    "status": ovpn_status,
                    "interface": "tun0"
                }
            except Exception as e:
                self.logger.error(f"Error checking OpenVPN status: {e}")
                servers_status["openvpn"] = {"status": "unknown", "interface": "tun0"}
            
            return servers_status
            
        except Exception as e:
            self.logger.error(f"Error collecting server status: {e}")
            return {}
    
    async def _broadcast_updates(self, system_metrics: Dict[str, Any], 
                                vpn_traffic: Dict[str, Any], 
                                server_status: Dict[str, Any]):
        """Broadcast updates via WebSocket"""
        try:
            # Send system metrics
            if system_metrics:
                await websocket_manager.broadcast_to_all({
                    "type": "system_metrics",
                    "data": system_metrics,
                    "timestamp": datetime.now().isoformat()
                })
            
            # Send VPN traffic updates
            if vpn_traffic:
                await websocket_manager.broadcast_to_all({
                    "type": "vpn_traffic",
                    "data": vpn_traffic,
                    "timestamp": datetime.now().isoformat()
                })
            
            # Send server status updates
            if server_status:
                for server_id, status_data in server_status.items():
                    server_status_obj = ServerStatus(
                        timestamp=datetime.now(),
                        server_id=server_id,
                        status=status_data["status"],
                        active_connections=vpn_traffic.get("active_connections", 0),
                        total_traffic={
                            "rx": vpn_traffic.get("total_rx", 0),
                            "tx": vpn_traffic.get("total_tx", 0)
                        },
                        cpu_usage=system_metrics.get("cpu_usage", 0),
                        memory_usage=system_metrics.get("memory_usage", 0)
                    )
                    await websocket_manager.send_server_status(server_status_obj)
            
            # Send dashboard stats
            dashboard_stats = {
                "active_servers": len([s for s in server_status.values() if s["status"] == "running"]),
                "active_clients": vpn_traffic.get("active_connections", 0),
                "total_traffic": vpn_traffic.get("total_rx", 0) + vpn_traffic.get("total_tx", 0),
                "current_bandwidth": self._calculate_current_bandwidth(vpn_traffic)
            }
            
            await websocket_manager.broadcast_to_all({
                "type": "dashboard_stats",
                "data": dashboard_stats,
                "timestamp": datetime.now().isoformat()
            })
            
        except Exception as e:
            self.logger.error(f"Error broadcasting updates: {e}")
    
    def _calculate_current_bandwidth(self, vpn_traffic: Dict[str, Any]) -> float:
        """Calculate current bandwidth usage in Mbps"""
        try:
            total_bytes = vpn_traffic.get("total_rx", 0) + vpn_traffic.get("total_tx", 0)
            # Convert to Mbps (assuming 5-second interval)
            bandwidth_mbps = (total_bytes * 8) / (1024 * 1024 * 5)
            return round(bandwidth_mbps, 2)
        except Exception:
            return 0.0
    
    async def _record_analytics(self, vpn_traffic: Dict[str, Any]):
        """Record traffic data for analytics"""
        try:
            if not vpn_traffic:
                return
            
            # Create traffic record
            traffic_record = TrafficRecord(
                timestamp=datetime.now(),
                client_id="system",  # System-wide traffic
                server_id="all",
                rx_bytes=vpn_traffic.get("total_rx", 0),
                tx_bytes=vpn_traffic.get("total_tx", 0),
                connection_duration=0,
                endpoint="system"
            )
            
            # Record in analytics
            traffic_analytics.record_traffic(traffic_record)
            
        except Exception as e:
            self.logger.error(f"Error recording analytics: {e}")

# Global background monitor instance
background_monitor = BackgroundMonitor() 