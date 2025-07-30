import os
import hashlib
import json
import logging
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional
from pathlib import Path
import psutil
import threading
import time

class IntrusionDetection:
    def __init__(self, config_dir: str = "/etc/vpn-panel"):
        self.config_dir = Path(config_dir)
        self.logger = logging.getLogger(__name__)
        
        self.file_hashes: Dict[str, str] = {}
        self.process_whitelist: Set[str] = set()
        self.port_whitelist: Set[int] = set()
        self.user_whitelist: Set[str] = set()
        
        self.monitoring_active = False
        self.monitor_thread = None
        
        self._load_whitelists()
        self._init_file_monitoring()
    
    def _load_whitelists(self):
        """Load security whitelists"""
        # Process whitelist
        self.process_whitelist = {
            "python3", "uvicorn", "nginx", "redis-server", 
            "wg-quick", "openvpn", "systemd", "sshd"
        }
        
        # Port whitelist
        self.port_whitelist = {22, 80, 443, 6379, 51820, 1194}
        
        # User whitelist
        self.user_whitelist = {"root", "vpn-panel", "www-data", "redis"}
    
    def _init_file_monitoring(self):
        """Initialize file monitoring"""
        critical_files = [
            "/etc/vpn-panel/secrets.json",
            "/var/lib/vpn-panel/users.db",
            "/etc/wireguard/wg0.conf",
            "/etc/openvpn/server.conf",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers"
        ]
        
        for file_path in critical_files:
            if os.path.exists(file_path):
                self.file_hashes[file_path] = self._calculate_file_hash(file_path)
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            self.logger.error(f"Failed to calculate hash for {file_path}: {e}")
            return ""
    
    def start_monitoring(self):
        """Start intrusion detection monitoring"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        self.logger.info("Intrusion detection monitoring started")
    
    def stop_monitoring(self):
        """Stop intrusion detection monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join()
        self.logger.info("Intrusion detection monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                self._check_file_integrity()
                self._check_process_anomalies()
                self._check_network_anomalies()
                self._check_user_anomalies()
                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                self.logger.error(f"Monitoring error: {e}")
                time.sleep(60)
    
    def _check_file_integrity(self):
        """Check file integrity"""
        for file_path, original_hash in self.file_hashes.items():
            if not os.path.exists(file_path):
                self._report_intrusion("file_deleted", f"Critical file deleted: {file_path}")
                continue
            
            current_hash = self._calculate_file_hash(file_path)
            if current_hash != original_hash:
                self._report_intrusion("file_modified", f"Critical file modified: {file_path}")
    
    def _check_process_anomalies(self):
        """Check for suspicious processes"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info['name']
                    username = proc_info['username']
                    
                    # Check for suspicious process names
                    suspicious_names = {
                        "nc", "netcat", "nmap", "hydra", "john", "hashcat",
                        "aircrack", "wireshark", "tcpdump", "snort"
                    }
                    
                    if proc_name in suspicious_names:
                        self._report_intrusion("suspicious_process", 
                                             f"Suspicious process detected: {proc_name} (PID: {proc_info['pid']})")
                    
                    # Check for processes running as unexpected users
                    if username not in self.user_whitelist and proc_name not in self.process_whitelist:
                        self._report_intrusion("unauthorized_process", 
                                             f"Unauthorized process: {proc_name} running as {username}")
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.logger.error(f"Process monitoring error: {e}")
    
    def _check_network_anomalies(self):
        """Check for network anomalies"""
        try:
            # Check listening ports
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    port = conn.laddr.port
                    if port not in self.port_whitelist:
                        self._report_intrusion("unauthorized_port", 
                                             f"Unauthorized listening port: {port}")
            
            # Check for unusual network connections
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    remote_ip = conn.raddr.ip if conn.raddr else None
                    if remote_ip and self._is_suspicious_ip(remote_ip):
                        self._report_intrusion("suspicious_connection", 
                                             f"Suspicious connection to: {remote_ip}")
                        
        except Exception as e:
            self.logger.error(f"Network monitoring error: {e}")
    
    def _check_user_anomalies(self):
        """Check for user anomalies"""
        try:
            # Check for failed login attempts
            failed_logins = self._get_failed_logins()
            if failed_logins > 10:
                self._report_intrusion("multiple_failed_logins", 
                                     f"Multiple failed login attempts: {failed_logins}")
            
            # Check for new users
            current_users = set(pwd.pw_name for pwd in pwd.getpwall())
            new_users = current_users - self.user_whitelist
            
            if new_users:
                self._report_intrusion("new_user_created", 
                                     f"New users detected: {new_users}")
                
        except Exception as e:
            self.logger.error(f"User monitoring error: {e}")
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP is suspicious"""
        # This is a basic implementation
        # In production, you'd check against threat intelligence feeds
        suspicious_patterns = [
            "192.168.1.",  # Local network (if not expected)
            "10.0.0.",     # VPN network (if not expected)
            "172.16.",     # Private network
        ]
        
        return any(ip.startswith(pattern) for pattern in suspicious_patterns)
    
    def _get_failed_logins(self) -> int:
        """Get count of failed login attempts"""
        try:
            result = subprocess.run([
                "grep", "-c", "Failed password", "/var/log/auth.log"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                return int(result.stdout.strip())
            return 0
        except Exception:
            return 0
    
    def _report_intrusion(self, intrusion_type: str, message: str):
        """Report intrusion detection"""
        from .log_monitor import log_monitor
        
        log_monitor.log_security_event(
            event_type="intrusion_detected",
            severity="high",
            source="hids",
            message=message,
            details={"intrusion_type": intrusion_type},
            ip_address=None
        )
        
        self.logger.warning(f"INTRUSION DETECTED: {message}")
    
    def get_system_baseline(self) -> Dict:
        """Get system security baseline"""
        try:
            baseline = {
                "timestamp": datetime.now().isoformat(),
                "file_hashes": self.file_hashes,
                "process_whitelist": list(self.process_whitelist),
                "port_whitelist": list(self.port_whitelist),
                "user_whitelist": list(self.user_whitelist),
                "system_info": self._get_system_info()
            }
            
            # Save baseline
            baseline_file = self.config_dir / "security_baseline.json"
            with open(baseline_file, 'w') as f:
                json.dump(baseline, f, indent=2)
            
            return baseline
            
        except Exception as e:
            self.logger.error(f"Failed to create baseline: {e}")
            return {}
    
    def _get_system_info(self) -> Dict:
        """Get system information"""
        try:
            return {
                "hostname": os.uname().nodename,
                "kernel": os.uname().release,
                "architecture": os.uname().machine,
                "uptime": time.time() - psutil.boot_time(),
                "cpu_count": psutil.cpu_count(),
                "memory_total": psutil.virtual_memory().total,
                "disk_usage": psutil.disk_usage('/').percent
            }
        except Exception as e:
            self.logger.error(f"Failed to get system info: {e}")
            return {}
    
    def verify_baseline(self) -> Dict:
        """Verify current system against baseline"""
        try:
            baseline_file = self.config_dir / "security_baseline.json"
            if not baseline_file.exists():
                return {"error": "No baseline found"}
            
            with open(baseline_file, 'r') as f:
                baseline = json.load(f)
            
            violations = []
            
            # Check file integrity
            for file_path, original_hash in baseline.get("file_hashes", {}).items():
                if os.path.exists(file_path):
                    current_hash = self._calculate_file_hash(file_path)
                    if current_hash != original_hash:
                        violations.append({
                            "type": "file_modified",
                            "file": file_path,
                            "severity": "high"
                        })
                else:
                    violations.append({
                        "type": "file_deleted",
                        "file": file_path,
                        "severity": "critical"
                    })
            
            # Check listening ports
            current_ports = set()
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    current_ports.add(conn.laddr.port)
            
            baseline_ports = set(baseline.get("port_whitelist", []))
            unauthorized_ports = current_ports - baseline_ports
            
            if unauthorized_ports:
                violations.append({
                    "type": "unauthorized_ports",
                    "ports": list(unauthorized_ports),
                    "severity": "medium"
                })
            
            return {
                "baseline_timestamp": baseline.get("timestamp"),
                "violations": violations,
                "total_violations": len(violations),
                "status": "clean" if not violations else "compromised"
            }
            
        except Exception as e:
            self.logger.error(f"Baseline verification error: {e}")
            return {"error": str(e)}
    
    def add_to_whitelist(self, whitelist_type: str, item: str):
        """Add item to whitelist"""
        if whitelist_type == "process":
            self.process_whitelist.add(item)
        elif whitelist_type == "port":
            self.port_whitelist.add(int(item))
        elif whitelist_type == "user":
            self.user_whitelist.add(item)
        else:
            raise ValueError(f"Invalid whitelist type: {whitelist_type}")
        
        self.logger.info(f"Added {item} to {whitelist_type} whitelist")
    
    def remove_from_whitelist(self, whitelist_type: str, item: str):
        """Remove item from whitelist"""
        if whitelist_type == "process":
            self.process_whitelist.discard(item)
        elif whitelist_type == "port":
            self.port_whitelist.discard(int(item))
        elif whitelist_type == "user":
            self.user_whitelist.discard(item)
        else:
            raise ValueError(f"Invalid whitelist type: {whitelist_type}")
        
        self.logger.info(f"Removed {item} from {whitelist_type} whitelist")
    
    def get_whitelists(self) -> Dict:
        """Get current whitelists"""
        return {
            "process_whitelist": list(self.process_whitelist),
            "port_whitelist": list(self.port_whitelist),
            "user_whitelist": list(self.user_whitelist)
        }

intrusion_detection = IntrusionDetection() 