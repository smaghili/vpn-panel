import sqlite3
import json
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import psutil

@dataclass
class TrafficRecord:
    timestamp: datetime
    client_id: str
    server_id: str
    rx_bytes: int
    tx_bytes: int
    connection_duration: int
    endpoint: str

@dataclass
class AnalyticsSummary:
    period: str
    total_traffic: int
    total_connections: int
    avg_bandwidth: float
    peak_bandwidth: float
    top_clients: List[Dict[str, Any]]
    top_servers: List[Dict[str, Any]]
    traffic_by_hour: List[Dict[str, Any]]

class TrafficAnalytics:
    def __init__(self, db_path: str = "/var/lib/vpn-panel/analytics.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self._init_database()
    
    def _init_database(self):
        """Initialize analytics database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS traffic_records (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME NOT NULL,
                        client_id TEXT NOT NULL,
                        server_id TEXT NOT NULL,
                        rx_bytes INTEGER NOT NULL,
                        tx_bytes INTEGER NOT NULL,
                        connection_duration INTEGER NOT NULL,
                        endpoint TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_traffic_timestamp 
                    ON traffic_records(timestamp)
                """)
                
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_traffic_client 
                    ON traffic_records(client_id)
                """)
                
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_traffic_server 
                    ON traffic_records(server_id)
                """)
                
                conn.commit()
        except Exception as e:
            self.logger.error(f"Error initializing analytics database: {e}")
    
    def record_traffic(self, traffic_record: TrafficRecord):
        """Record traffic data"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO traffic_records 
                    (timestamp, client_id, server_id, rx_bytes, tx_bytes, 
                     connection_duration, endpoint)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    traffic_record.timestamp.isoformat(),
                    traffic_record.client_id,
                    traffic_record.server_id,
                    traffic_record.rx_bytes,
                    traffic_record.tx_bytes,
                    traffic_record.connection_duration,
                    traffic_record.endpoint
                ))
                conn.commit()
        except Exception as e:
            self.logger.error(f"Error recording traffic: {e}")
    
    def get_traffic_summary(self, period: str = "24h") -> AnalyticsSummary:
        """Get traffic summary for specified period"""
        try:
            end_time = datetime.now()
            
            if period == "1h":
                start_time = end_time - timedelta(hours=1)
            elif period == "6h":
                start_time = end_time - timedelta(hours=6)
            elif period == "24h":
                start_time = end_time - timedelta(days=1)
            elif period == "7d":
                start_time = end_time - timedelta(days=7)
            elif period == "30d":
                start_time = end_time - timedelta(days=30)
            else:
                start_time = end_time - timedelta(hours=24)
            
            with sqlite3.connect(self.db_path) as conn:
                # Total traffic and connections
                cursor = conn.execute("""
                    SELECT 
                        SUM(rx_bytes + tx_bytes) as total_traffic,
                        COUNT(DISTINCT client_id) as total_connections,
                        AVG((rx_bytes + tx_bytes) * 8.0 / 1024 / 1024) as avg_bandwidth,
                        MAX((rx_bytes + tx_bytes) * 8.0 / 1024 / 1024) as peak_bandwidth
                    FROM traffic_records 
                    WHERE timestamp BETWEEN ? AND ?
                """, (start_time.isoformat(), end_time.isoformat()))
                
                row = cursor.fetchone()
                total_traffic = row[0] or 0
                total_connections = row[1] or 0
                avg_bandwidth = row[2] or 0
                peak_bandwidth = row[3] or 0
                
                # Top clients
                cursor = conn.execute("""
                    SELECT 
                        client_id,
                        SUM(rx_bytes + tx_bytes) as total_traffic,
                        COUNT(*) as connection_count
                    FROM traffic_records 
                    WHERE timestamp BETWEEN ? AND ?
                    GROUP BY client_id
                    ORDER BY total_traffic DESC
                    LIMIT 10
                """, (start_time.isoformat(), end_time.isoformat()))
                
                top_clients = []
                for row in cursor.fetchall():
                    top_clients.append({
                        "client_id": row[0],
                        "total_traffic": row[1],
                        "connection_count": row[2]
                    })
                
                # Top servers
                cursor = conn.execute("""
                    SELECT 
                        server_id,
                        SUM(rx_bytes + tx_bytes) as total_traffic,
                        COUNT(DISTINCT client_id) as unique_clients
                    FROM traffic_records 
                    WHERE timestamp BETWEEN ? AND ?
                    GROUP BY server_id
                    ORDER BY total_traffic DESC
                    LIMIT 10
                """, (start_time.isoformat(), end_time.isoformat()))
                
                top_servers = []
                for row in cursor.fetchall():
                    top_servers.append({
                        "server_id": row[0],
                        "total_traffic": row[1],
                        "unique_clients": row[2]
                    })
                
                # Traffic by hour
                cursor = conn.execute("""
                    SELECT 
                        strftime('%H', timestamp) as hour,
                        SUM(rx_bytes + tx_bytes) as total_traffic
                    FROM traffic_records 
                    WHERE timestamp BETWEEN ? AND ?
                    GROUP BY hour
                    ORDER BY hour
                """, (start_time.isoformat(), end_time.isoformat()))
                
                traffic_by_hour = []
                for row in cursor.fetchall():
                    traffic_by_hour.append({
                        "hour": int(row[0]),
                        "total_traffic": row[1]
                    })
                
                return AnalyticsSummary(
                    period=period,
                    total_traffic=total_traffic,
                    total_connections=total_connections,
                    avg_bandwidth=avg_bandwidth,
                    peak_bandwidth=peak_bandwidth,
                    top_clients=top_clients,
                    top_servers=top_servers,
                    traffic_by_hour=traffic_by_hour
                )
                
        except Exception as e:
            self.logger.error(f"Error getting traffic summary: {e}")
            return AnalyticsSummary(
                period=period,
                total_traffic=0,
                total_connections=0,
                avg_bandwidth=0,
                peak_bandwidth=0,
                top_clients=[],
                top_servers=[],
                traffic_by_hour=[]
            )
    
    def get_client_analytics(self, client_id: str, period: str = "24h") -> Dict[str, Any]:
        """Get analytics for specific client"""
        try:
            end_time = datetime.now()
            
            if period == "1h":
                start_time = end_time - timedelta(hours=1)
            elif period == "24h":
                start_time = end_time - timedelta(days=1)
            elif period == "7d":
                start_time = end_time - timedelta(days=7)
            else:
                start_time = end_time - timedelta(hours=24)
            
            with sqlite3.connect(self.db_path) as conn:
                # Client summary
                cursor = conn.execute("""
                    SELECT 
                        SUM(rx_bytes) as total_rx,
                        SUM(tx_bytes) as total_tx,
                        COUNT(*) as connection_count,
                        AVG(connection_duration) as avg_duration,
                        MAX(timestamp) as last_connection
                    FROM traffic_records 
                    WHERE client_id = ? AND timestamp BETWEEN ? AND ?
                """, (client_id, start_time.isoformat(), end_time.isoformat()))
                
                row = cursor.fetchone()
                if not row or not row[0]:
                    return {"error": "No data found for client"}
                
                total_rx = row[0] or 0
                total_tx = row[1] or 0
                connection_count = row[2] or 0
                avg_duration = row[3] or 0
                last_connection = row[4]
                
                # Traffic by hour for this client
                cursor = conn.execute("""
                    SELECT 
                        strftime('%H', timestamp) as hour,
                        SUM(rx_bytes + tx_bytes) as total_traffic
                    FROM traffic_records 
                    WHERE client_id = ? AND timestamp BETWEEN ? AND ?
                    GROUP BY hour
                    ORDER BY hour
                """, (client_id, start_time.isoformat(), end_time.isoformat()))
                
                traffic_by_hour = []
                for row in cursor.fetchall():
                    traffic_by_hour.append({
                        "hour": int(row[0]),
                        "total_traffic": row[1]
                    })
                
                return {
                    "client_id": client_id,
                    "period": period,
                    "total_rx_bytes": total_rx,
                    "total_tx_bytes": total_tx,
                    "total_traffic": total_rx + total_tx,
                    "connection_count": connection_count,
                    "avg_connection_duration": avg_duration,
                    "last_connection": last_connection,
                    "traffic_by_hour": traffic_by_hour,
                    "avg_bandwidth_mbps": ((total_rx + total_tx) * 8) / (1024 * 1024) / 24  # Assuming 24h period
                }
                
        except Exception as e:
            self.logger.error(f"Error getting client analytics: {e}")
            return {"error": f"Error getting client analytics: {e}"}
    
    def get_server_analytics(self, server_id: str, period: str = "24h") -> Dict[str, Any]:
        """Get analytics for specific server"""
        try:
            end_time = datetime.now()
            
            if period == "1h":
                start_time = end_time - timedelta(hours=1)
            elif period == "24h":
                start_time = end_time - timedelta(days=1)
            elif period == "7d":
                start_time = end_time - timedelta(days=7)
            else:
                start_time = end_time - timedelta(hours=24)
            
            with sqlite3.connect(self.db_path) as conn:
                # Server summary
                cursor = conn.execute("""
                    SELECT 
                        SUM(rx_bytes) as total_rx,
                        SUM(tx_bytes) as total_tx,
                        COUNT(DISTINCT client_id) as unique_clients,
                        COUNT(*) as total_connections,
                        AVG(connection_duration) as avg_duration
                    FROM traffic_records 
                    WHERE server_id = ? AND timestamp BETWEEN ? AND ?
                """, (server_id, start_time.isoformat(), end_time.isoformat()))
                
                row = cursor.fetchone()
                if not row or not row[0]:
                    return {"error": "No data found for server"}
                
                total_rx = row[0] or 0
                total_tx = row[1] or 0
                unique_clients = row[2] or 0
                total_connections = row[3] or 0
                avg_duration = row[4] or 0
                
                # Top clients for this server
                cursor = conn.execute("""
                    SELECT 
                        client_id,
                        SUM(rx_bytes + tx_bytes) as total_traffic,
                        COUNT(*) as connection_count
                    FROM traffic_records 
                    WHERE server_id = ? AND timestamp BETWEEN ? AND ?
                    GROUP BY client_id
                    ORDER BY total_traffic DESC
                    LIMIT 10
                """, (server_id, start_time.isoformat(), end_time.isoformat()))
                
                top_clients = []
                for row in cursor.fetchall():
                    top_clients.append({
                        "client_id": row[0],
                        "total_traffic": row[1],
                        "connection_count": row[2]
                    })
                
                return {
                    "server_id": server_id,
                    "period": period,
                    "total_rx_bytes": total_rx,
                    "total_tx_bytes": total_tx,
                    "total_traffic": total_rx + total_tx,
                    "unique_clients": unique_clients,
                    "total_connections": total_connections,
                    "avg_connection_duration": avg_duration,
                    "top_clients": top_clients,
                    "avg_bandwidth_mbps": ((total_rx + total_tx) * 8) / (1024 * 1024) / 24
                }
                
        except Exception as e:
            self.logger.error(f"Error getting server analytics: {e}")
            return {"error": f"Error getting server analytics: {e}"}
    
    def cleanup_old_data(self, days: int = 30):
        """Clean up old traffic data"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    DELETE FROM traffic_records 
                    WHERE timestamp < ?
                """, (cutoff_date.isoformat(),))
                conn.commit()
                
            self.logger.info(f"Cleaned up traffic data older than {days} days")
            
        except Exception as e:
            self.logger.error(f"Error cleaning up old data: {e}")
    
    def export_analytics(self, start_date: datetime, end_date: datetime, 
                        format: str = "json") -> str:
        """Export analytics data"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT * FROM traffic_records 
                    WHERE timestamp BETWEEN ? AND ?
                    ORDER BY timestamp
                """, (start_date.isoformat(), end_date.isoformat()))
                
                rows = cursor.fetchall()
                
                if format == "json":
                    data = []
                    for row in rows:
                        data.append({
                            "timestamp": row[1],
                            "client_id": row[2],
                            "server_id": row[3],
                            "rx_bytes": row[4],
                            "tx_bytes": row[5],
                            "connection_duration": row[6],
                            "endpoint": row[7]
                        })
                    return json.dumps(data, indent=2)
                else:
                    # CSV format
                    csv_data = "timestamp,client_id,server_id,rx_bytes,tx_bytes,connection_duration,endpoint\n"
                    for row in rows:
                        csv_data += f"{row[1]},{row[2]},{row[3]},{row[4]},{row[5]},{row[6]},{row[7]}\n"
                    return csv_data
                    
        except Exception as e:
            self.logger.error(f"Error exporting analytics: {e}")
            return ""

# Global analytics instance
traffic_analytics = TrafficAnalytics() 