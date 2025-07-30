import os
import json
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pathlib import Path
import subprocess
import re

class LogAggregator:
    def __init__(self, log_dir: str = "/var/log/vpn-panel"):
        self.log_dir = Path(log_dir)
        self.logger = logging.getLogger(__name__)
        
        self.aggregated_logs: List[Dict] = []
        self.log_sources = {
            "vpn_panel": "/var/log/vpn-panel",
            "system": "/var/log/syslog",
            "auth": "/var/log/auth.log",
            "wireguard": "/var/log/wireguard",
            "openvpn": "/var/log/openvpn",
            "nginx": "/var/log/nginx",
            "redis": "/var/log/redis"
        }
        
        self._init_aggregation()
    
    def _init_aggregation(self):
        """Initialize log aggregation"""
        self.aggregated_file = self.log_dir / "aggregated.log"
        if not self.aggregated_file.exists():
            self.aggregated_file.touch(mode=0o600)
    
    def collect_logs(self, hours: int = 24) -> Dict:
        """Collect logs from all sources"""
        try:
            all_logs = []
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            for source_name, source_path in self.log_sources.items():
                if os.path.exists(source_path):
                    logs = self._read_log_source(source_path, cutoff_time)
                    for log_entry in logs:
                        log_entry["source"] = source_name
                        all_logs.append(log_entry)
            
            # Sort by timestamp
            all_logs.sort(key=lambda x: x.get("timestamp", ""))
            
            # Save aggregated logs
            self._save_aggregated_logs(all_logs)
            
            return {
                "total_logs": len(all_logs),
                "sources": list(self.log_sources.keys()),
                "time_range": f"Last {hours} hours",
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Log collection error: {e}")
            return {"error": str(e)}
    
    def _read_log_source(self, source_path: str, cutoff_time: datetime) -> List[Dict]:
        """Read logs from a specific source"""
        logs = []
        
        try:
            if os.path.isfile(source_path):
                logs.extend(self._read_log_file(source_path, cutoff_time))
            elif os.path.isdir(source_path):
                for log_file in Path(source_path).glob("*.log"):
                    logs.extend(self._read_log_file(str(log_file), cutoff_time))
        except Exception as e:
            self.logger.error(f"Failed to read log source {source_path}: {e}")
        
        return logs
    
    def _read_log_file(self, file_path: str, cutoff_time: datetime) -> List[Dict]:
        """Read individual log file"""
        logs = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        log_entry = self._parse_log_line(line.strip(), file_path, line_num)
                        if log_entry and log_entry.get("timestamp"):
                            log_time = datetime.fromisoformat(log_entry["timestamp"])
                            if log_time >= cutoff_time:
                                logs.append(log_entry)
                    except Exception as e:
                        self.logger.debug(f"Failed to parse line {line_num} in {file_path}: {e}")
                        continue
        except Exception as e:
            self.logger.error(f"Failed to read log file {file_path}: {e}")
        
        return logs
    
    def _parse_log_line(self, line: str, file_path: str, line_num: int) -> Optional[Dict]:
        """Parse a single log line"""
        if not line:
            return None
        
        # Try to extract timestamp and message
        timestamp = None
        message = line
        level = "info"
        
        # Common log patterns
        patterns = [
            # Standard syslog format
            r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s*(.*)$',
            # ISO timestamp format
            r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s*(.*)$',
            # JSON format
            r'^(\{.*\})$'
        ]
        
        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                if pattern == patterns[0]:  # syslog format
                    timestamp_str = match.group(1)
                    hostname = match.group(2)
                    service = match.group(3)
                    message = match.group(4)
                    
                    # Convert to ISO format
                    current_year = datetime.now().year
                    timestamp = f"{current_year} {timestamp_str}"
                    try:
                        timestamp = datetime.strptime(timestamp, "%Y %b %d %H:%M:%S").isoformat()
                    except:
                        timestamp = None
                
                elif pattern == patterns[1]:  # ISO format
                    timestamp = match.group(1)
                    message = match.group(2)
                
                elif pattern == patterns[2]:  # JSON format
                    try:
                        json_data = json.loads(match.group(1))
                        timestamp = json_data.get("timestamp")
                        message = json_data.get("message", line)
                        level = json_data.get("level", "info")
                    except:
                        pass
                
                break
        
        # Determine log level from message
        if any(word in message.lower() for word in ["error", "failed", "failure"]):
            level = "error"
        elif any(word in message.lower() for word in ["warning", "warn"]):
            level = "warning"
        elif any(word in message.lower() for word in ["debug"]):
            level = "debug"
        
        return {
            "timestamp": timestamp or datetime.now().isoformat(),
            "message": message,
            "level": level,
            "file": file_path,
            "line": line_num,
            "raw_line": line
        }
    
    def _save_aggregated_logs(self, logs: List[Dict]):
        """Save aggregated logs to file"""
        try:
            with open(self.aggregated_file, 'w') as f:
                for log_entry in logs:
                    f.write(json.dumps(log_entry) + "\n")
            
            self.aggregated_logs = logs
            
        except Exception as e:
            self.logger.error(f"Failed to save aggregated logs: {e}")
    
    def search_logs(self, query: str, hours: int = 24, level: Optional[str] = None) -> List[Dict]:
        """Search logs with filters"""
        try:
            if not self.aggregated_logs:
                self.collect_logs(hours)
            
            results = []
            query_lower = query.lower()
            
            for log_entry in self.aggregated_logs:
                # Check if log entry matches query
                if (query_lower in log_entry.get("message", "").lower() or
                    query_lower in log_entry.get("raw_line", "").lower()):
                    
                    # Apply level filter
                    if level and log_entry.get("level") != level:
                        continue
                    
                    results.append(log_entry)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Log search error: {e}")
            return []
    
    def get_log_statistics(self, hours: int = 24) -> Dict:
        """Get log statistics"""
        try:
            if not self.aggregated_logs:
                self.collect_logs(hours)
            
            stats = {
                "total_logs": len(self.aggregated_logs),
                "level_distribution": {},
                "source_distribution": {},
                "hourly_distribution": {},
                "top_messages": {},
                "error_count": 0,
                "warning_count": 0
            }
            
            for log_entry in self.aggregated_logs:
                # Level distribution
                level = log_entry.get("level", "unknown")
                stats["level_distribution"][level] = stats["level_distribution"].get(level, 0) + 1
                
                # Source distribution
                source = log_entry.get("source", "unknown")
                stats["source_distribution"][source] = stats["source_distribution"].get(source, 0) + 1
                
                # Hourly distribution
                try:
                    timestamp = datetime.fromisoformat(log_entry.get("timestamp", ""))
                    hour = timestamp.strftime("%Y-%m-%d %H:00")
                    stats["hourly_distribution"][hour] = stats["hourly_distribution"].get(hour, 0) + 1
                except:
                    pass
                
                # Count errors and warnings
                if level == "error":
                    stats["error_count"] += 1
                elif level == "warning":
                    stats["warning_count"] += 1
                
                # Top messages
                message = log_entry.get("message", "")
                if message:
                    # Extract first 50 characters as key
                    key = message[:50] + "..." if len(message) > 50 else message
                    stats["top_messages"][key] = stats["top_messages"].get(key, 0) + 1
            
            # Sort top messages
            stats["top_messages"] = dict(
                sorted(stats["top_messages"].items(), 
                      key=lambda x: x[1], reverse=True)[:10]
            )
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Log statistics error: {e}")
            return {"error": str(e)}
    
    def export_logs(self, format: str = "json", hours: int = 24) -> str:
        """Export logs in specified format"""
        try:
            if not self.aggregated_logs:
                self.collect_logs(hours)
            
            export_file = self.log_dir / f"exported_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            if format == "json":
                with open(f"{export_file}.json", 'w') as f:
                    json.dump(self.aggregated_logs, f, indent=2)
                return f"{export_file}.json"
            
            elif format == "csv":
                import csv
                with open(f"{export_file}.csv", 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=[
                        "timestamp", "level", "source", "message", "file", "line"
                    ])
                    writer.writeheader()
                    for log_entry in self.aggregated_logs:
                        writer.writerow({
                            "timestamp": log_entry.get("timestamp", ""),
                            "level": log_entry.get("level", ""),
                            "source": log_entry.get("source", ""),
                            "message": log_entry.get("message", ""),
                            "file": log_entry.get("file", ""),
                            "line": log_entry.get("line", "")
                        })
                return f"{export_file}.csv"
            
            else:
                raise ValueError(f"Unsupported format: {format}")
                
        except Exception as e:
            self.logger.error(f"Log export error: {e}")
            return ""
    
    def cleanup_old_logs(self, days: int = 30):
        """Clean up old log files"""
        try:
            cutoff_time = datetime.now() - timedelta(days=days)
            deleted_count = 0
            
            for source_path in self.log_sources.values():
                if os.path.exists(source_path):
                    if os.path.isfile(source_path):
                        if self._should_delete_file(source_path, cutoff_time):
                            os.remove(source_path)
                            deleted_count += 1
                    elif os.path.isdir(source_path):
                        for log_file in Path(source_path).glob("*.log.*"):
                            if self._should_delete_file(str(log_file), cutoff_time):
                                log_file.unlink()
                                deleted_count += 1
            
            self.logger.info(f"Cleaned up {deleted_count} old log files")
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Log cleanup error: {e}")
            return 0
    
    def _should_delete_file(self, file_path: str, cutoff_time: datetime) -> bool:
        """Check if file should be deleted based on age"""
        try:
            file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
            return file_time < cutoff_time
        except:
            return False

log_aggregator = LogAggregator() 