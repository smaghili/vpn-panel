import subprocess
import logging
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

@dataclass
class BandwidthLimit:
    client_id: str
    download_limit: int  # Mbps
    upload_limit: int    # Mbps
    daily_limit: int     # GB
    monthly_limit: int   # GB
    current_usage: int   # bytes
    reset_date: datetime

class BandwidthManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.limits: Dict[str, BandwidthLimit] = {}
        self.traffic_counters: Dict[str, Dict[str, int]] = {}
    
    def set_client_bandwidth_limit(self, client_id: str, download_mbps: int, 
                                  upload_mbps: int, daily_gb: int = 0, 
                                  monthly_gb: int = 0) -> bool:
        """Set bandwidth limits for a client"""
        try:
            # Create tc qdisc for WireGuard interface
            interface = "wg0"
            
            # Add qdisc if not exists
            self._run_tc_command([
                "qdisc", "add", "dev", interface, 
                "root", "handle", "1:", "htb", "default", "30"
            ], ignore_errors=True)
            
            # Create class for this client
            class_id = f"1:{hash(client_id) % 1000}"
            
            # Set download limit
            self._run_tc_command([
                "class", "add", "dev", interface,
                "parent", "1:", "classid", class_id,
                "htb", "rate", f"{download_mbps}mbit", "ceil", f"{download_mbps}mbit"
            ])
            
            # Set upload limit (using iptables)
            self._set_upload_limit(client_id, upload_mbps)
            
            # Store limit information
            self.limits[client_id] = BandwidthLimit(
                client_id=client_id,
                download_limit=download_mbps,
                upload_limit=upload_mbps,
                daily_limit=daily_gb * 1024 * 1024 * 1024,  # Convert to bytes
                monthly_limit=monthly_gb * 1024 * 1024 * 1024,
                current_usage=0,
                reset_date=datetime.now()
            )
            
            self.logger.info(f"Bandwidth limit set for client {client_id}: {download_mbps}Mbps down, {upload_mbps}Mbps up")
            return True
            
        except Exception as e:
            self.logger.error(f"Error setting bandwidth limit for client {client_id}: {e}")
            return False
    
    def _set_upload_limit(self, client_id: str, upload_mbps: int):
        """Set upload limit using iptables"""
        try:
            # Create custom chain for this client
            chain_name = f"CLIENT_{client_id[:8]}"
            
            # Create chain
            self._run_iptables_command(["-N", chain_name], ignore_errors=True)
            
            # Add rate limiting rule
            self._run_iptables_command([
                "-A", chain_name,
                "-m", "limit", "--limit", f"{upload_mbps}m", "--limit-burst", "10",
                "-j", "ACCEPT"
            ])
            
            # Add drop rule for excess traffic
            self._run_iptables_command([
                "-A", chain_name, "-j", "DROP"
            ])
            
            # Add rule to forward chain
            self._run_iptables_command([
                "-A", "FORWARD", "-s", f"10.0.0.{hash(client_id) % 254 + 1}/32", 
                "-j", chain_name
            ])
            
        except Exception as e:
            self.logger.error(f"Error setting upload limit: {e}")
    
    def remove_client_bandwidth_limit(self, client_id: str) -> bool:
        """Remove bandwidth limits for a client"""
        try:
            interface = "wg0"
            class_id = f"1:{hash(client_id) % 1000}"
            
            # Remove tc class
            self._run_tc_command([
                "class", "del", "dev", interface,
                "parent", "1:", "classid", class_id
            ], ignore_errors=True)
            
            # Remove iptables rules
            chain_name = f"CLIENT_{client_id[:8]}"
            self._run_iptables_command([
                "-D", "FORWARD", "-s", f"10.0.0.{hash(client_id) % 254 + 1}/32", 
                "-j", chain_name
            ], ignore_errors=True)
            
            # Flush and delete chain
            self._run_iptables_command(["-F", chain_name], ignore_errors=True)
            self._run_iptables_command(["-X", chain_name], ignore_errors=True)
            
            # Remove from limits
            if client_id in self.limits:
                del self.limits[client_id]
            
            self.logger.info(f"Bandwidth limit removed for client {client_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error removing bandwidth limit for client {client_id}: {e}")
            return False
    
    def get_client_traffic_stats(self, client_id: str) -> Dict[str, int]:
        """Get current traffic statistics for a client"""
        try:
            # Get tc statistics
            result = self._run_tc_command([
                "class", "show", "dev", "wg0"
            ], capture_output=True)
            
            if result:
                return self._parse_tc_stats(result, client_id)
            
            return {"rx_bytes": 0, "tx_bytes": 0}
            
        except Exception as e:
            self.logger.error(f"Error getting traffic stats for client {client_id}: {e}")
            return {"rx_bytes": 0, "tx_bytes": 0}
    
    def _parse_tc_stats(self, output: str, client_id: str) -> Dict[str, int]:
        """Parse tc statistics output"""
        class_id = f"1:{hash(client_id) % 1000}"
        stats = {"rx_bytes": 0, "tx_bytes": 0}
        
        lines = output.split('\n')
        for line in lines:
            if class_id in line and "Sent" in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == "Sent":
                        stats["tx_bytes"] = int(parts[i + 1])
                    elif part == "Received":
                        stats["rx_bytes"] = int(parts[i + 1])
                break
        
        return stats
    
    def check_bandwidth_limits(self, client_id: str) -> Tuple[bool, str]:
        """Check if client has exceeded bandwidth limits"""
        if client_id not in self.limits:
            return True, "No limits set"
        
        limit = self.limits[client_id]
        stats = self.get_client_traffic_stats(client_id)
        
        # Check daily limit
        if limit.daily_limit > 0:
            daily_usage = stats["rx_bytes"] + stats["tx_bytes"]
            if daily_usage > limit.daily_limit:
                return False, "Daily bandwidth limit exceeded"
        
        # Check monthly limit
        if limit.monthly_limit > 0:
            monthly_usage = stats["rx_bytes"] + stats["tx_bytes"]
            if monthly_usage > limit.monthly_limit:
                return False, "Monthly bandwidth limit exceeded"
        
        return True, "Within limits"
    
    def reset_daily_usage(self, client_id: str):
        """Reset daily usage counter"""
        if client_id in self.limits:
            self.limits[client_id].current_usage = 0
            self.limits[client_id].reset_date = datetime.now()
    
    def get_all_limits(self) -> Dict[str, BandwidthLimit]:
        """Get all bandwidth limits"""
        return self.limits.copy()
    
    def _run_tc_command(self, args: List[str], capture_output: bool = False, 
                       ignore_errors: bool = False) -> Optional[str]:
        """Run tc command"""
        try:
            result = subprocess.run(
                ["tc"] + args,
                capture_output=capture_output,
                text=True,
                check=not ignore_errors
            )
            return result.stdout if capture_output else None
        except subprocess.CalledProcessError as e:
            if not ignore_errors:
                self.logger.error(f"tc command failed: {e}")
            return None
    
    def _run_iptables_command(self, args: List[str], ignore_errors: bool = False) -> bool:
        """Run iptables command"""
        try:
            subprocess.run(
                ["iptables"] + args,
                check=not ignore_errors,
                capture_output=True
            )
            return True
        except subprocess.CalledProcessError as e:
            if not ignore_errors:
                self.logger.error(f"iptables command failed: {e}")
            return False

# Global bandwidth manager instance
bandwidth_manager = BandwidthManager() 