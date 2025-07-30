import os
import json
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from pathlib import Path
import psutil
import subprocess

@dataclass
class Alert:
    id: str
    timestamp: datetime
    type: str
    severity: str
    message: str
    details: Dict
    acknowledged: bool = False
    resolved: bool = False

@dataclass
class AlertRule:
    name: str
    condition: Callable
    severity: str
    message_template: str
    enabled: bool = True
    check_interval: int = 60

class MonitoringAlerts:
    def __init__(self, config_dir: str = "/etc/vpn-panel"):
        self.config_dir = Path(config_dir)
        self.logger = logging.getLogger(__name__)
        
        self.alerts: List[Alert] = []
        self.alert_rules: Dict[str, AlertRule] = {}
        self.monitoring_active = False
        self.monitor_task = None
        
        self._init_alert_rules()
        self._load_alerts()
    
    def _init_alert_rules(self):
        """Initialize monitoring alert rules"""
        self.alert_rules = {
            "high_cpu": AlertRule(
                name="High CPU Usage",
                condition=self._check_high_cpu,
                severity="warning",
                message_template="CPU usage is {cpu_percent}% (threshold: 80%)",
                check_interval=60
            ),
            "high_memory": AlertRule(
                name="High Memory Usage",
                condition=self._check_high_memory,
                severity="warning",
                message_template="Memory usage is {memory_percent}% (threshold: 85%)",
                check_interval=60
            ),
            "high_disk": AlertRule(
                name="High Disk Usage",
                condition=self._check_high_disk,
                severity="warning",
                message_template="Disk usage is {disk_percent}% (threshold: 90%)",
                check_interval=300
            ),
            "service_down": AlertRule(
                name="Service Down",
                condition=self._check_services,
                severity="critical",
                message_template="Service {service} is down",
                check_interval=30
            ),
            "high_network": AlertRule(
                name="High Network Usage",
                condition=self._check_network_usage,
                severity="info",
                message_template="High network activity detected",
                check_interval=60
            ),
            "security_events": AlertRule(
                name="Security Events",
                condition=self._check_security_events,
                severity="high",
                message_template="Multiple security events detected",
                check_interval=60
            ),
            "backup_failure": AlertRule(
                name="Backup Failure",
                condition=self._check_backup_status,
                severity="critical",
                message_template="Backup failed or missing",
                check_interval=3600
            ),
            "certificate_expiry": AlertRule(
                name="Certificate Expiry",
                condition=self._check_certificates,
                severity="warning",
                message_template="Certificate expires in {days} days",
                check_interval=86400
            )
        }
    
    def _load_alerts(self):
        """Load alerts from file"""
        alerts_file = self.config_dir / "alerts.json"
        if alerts_file.exists():
            try:
                with open(alerts_file, 'r') as f:
                    alerts_data = json.load(f)
                    for alert_data in alerts_data:
                        alert = Alert(
                            id=alert_data["id"],
                            timestamp=datetime.fromisoformat(alert_data["timestamp"]),
                            type=alert_data["type"],
                            severity=alert_data["severity"],
                            message=alert_data["message"],
                            details=alert_data["details"],
                            acknowledged=alert_data.get("acknowledged", False),
                            resolved=alert_data.get("resolved", False)
                        )
                        self.alerts.append(alert)
            except Exception as e:
                self.logger.error(f"Failed to load alerts: {e}")
    
    def _save_alerts(self):
        """Save alerts to file"""
        alerts_file = self.config_dir / "alerts.json"
        try:
            alerts_data = []
            for alert in self.alerts:
                alerts_data.append({
                    "id": alert.id,
                    "timestamp": alert.timestamp.isoformat(),
                    "type": alert.type,
                    "severity": alert.severity,
                    "message": alert.message,
                    "details": alert.details,
                    "acknowledged": alert.acknowledged,
                    "resolved": alert.resolved
                })
            
            with open(alerts_file, 'w') as f:
                json.dump(alerts_data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to save alerts: {e}")
    
    def start_monitoring(self):
        """Start monitoring and alerting"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitor_task = asyncio.create_task(self._monitor_loop())
        self.logger.info("Monitoring and alerting started")
    
    def stop_monitoring(self):
        """Stop monitoring and alerting"""
        self.monitoring_active = False
        if self.monitor_task:
            self.monitor_task.cancel()
        self.logger.info("Monitoring and alerting stopped")
    
    async def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                for rule_name, rule in self.alert_rules.items():
                    if rule.enabled:
                        await self._check_alert_rule(rule_name, rule)
                
                # Wait before next check
                await asyncio.sleep(30)
                
            except Exception as e:
                self.logger.error(f"Monitoring error: {e}")
                await asyncio.sleep(60)
    
    async def _check_alert_rule(self, rule_name: str, rule: AlertRule):
        """Check a specific alert rule"""
        try:
            result = rule.condition()
            if result:
                # Create alert
                alert_id = f"{rule_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                message = rule.message_template.format(**result)
                
                alert = Alert(
                    id=alert_id,
                    timestamp=datetime.now(),
                    type=rule_name,
                    severity=rule.severity,
                    message=message,
                    details=result
                )
                
                self.alerts.append(alert)
                self._save_alerts()
                
                # Log alert
                self.logger.warning(f"ALERT: {message}")
                
                # Send notification (placeholder)
                await self._send_notification(alert)
                
        except Exception as e:
            self.logger.error(f"Alert rule check error for {rule_name}: {e}")
    
    def _check_high_cpu(self) -> Optional[Dict]:
        """Check for high CPU usage"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 80:
                return {"cpu_percent": cpu_percent}
        except Exception as e:
            self.logger.error(f"CPU check error: {e}")
        return None
    
    def _check_high_memory(self) -> Optional[Dict]:
        """Check for high memory usage"""
        try:
            memory = psutil.virtual_memory()
            if memory.percent > 85:
                return {"memory_percent": memory.percent}
        except Exception as e:
            self.logger.error(f"Memory check error: {e}")
        return None
    
    def _check_high_disk(self) -> Optional[Dict]:
        """Check for high disk usage"""
        try:
            disk = psutil.disk_usage('/')
            if disk.percent > 90:
                return {"disk_percent": disk.percent}
        except Exception as e:
            self.logger.error(f"Disk check error: {e}")
        return None
    
    def _check_services(self) -> Optional[Dict]:
        """Check if critical services are running"""
        critical_services = ["vpn-panel", "redis-server", "wg-quick@wg0"]
        
        for service in critical_services:
            try:
                result = subprocess.run([
                    "systemctl", "is-active", service
                ], capture_output=True, text=True)
                
                if result.returncode != 0:
                    return {"service": service, "status": result.stdout.strip()}
                    
            except Exception as e:
                self.logger.error(f"Service check error for {service}: {e}")
        
        return None
    
    def _check_network_usage(self) -> Optional[Dict]:
        """Check for high network usage"""
        try:
            net_io = psutil.net_io_counters()
            # This is a simplified check - in production you'd track over time
            if net_io.bytes_sent > 1e9 or net_io.bytes_recv > 1e9:  # 1GB
                return {
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv
                }
        except Exception as e:
            self.logger.error(f"Network check error: {e}")
        return None
    
    def _check_security_events(self) -> Optional[Dict]:
        """Check for security events"""
        try:
            from .log_monitor import log_monitor
            stats = log_monitor.get_security_stats()
            
            if stats.get("total_events_1h", 0) > 100:
                return {
                    "events_1h": stats.get("total_events_1h", 0),
                    "blocked_ips": stats.get("blocked_ips", 0)
                }
        except Exception as e:
            self.logger.error(f"Security events check error: {e}")
        return None
    
    def _check_backup_status(self) -> Optional[Dict]:
        """Check backup status"""
        try:
            from .backup.backup_manager import backup_manager
            backups = backup_manager.list_backups()
            
            if not backups:
                return {"backup_count": 0}
            
            # Check if latest backup is recent
            latest_backup = max(backups, key=lambda b: b.timestamp)
            if datetime.now() - latest_backup.timestamp > timedelta(days=1):
                return {
                    "latest_backup": latest_backup.timestamp.isoformat(),
                    "days_old": (datetime.now() - latest_backup.timestamp).days
                }
                
        except Exception as e:
            self.logger.error(f"Backup check error: {e}")
        return None
    
    def _check_certificates(self) -> Optional[Dict]:
        """Check certificate expiry"""
        try:
            # Check SSL certificates (placeholder)
            # In production, you'd check actual certificates
            return None
        except Exception as e:
            self.logger.error(f"Certificate check error: {e}")
        return None
    
    async def _send_notification(self, alert: Alert):
        """Send notification for alert"""
        # Placeholder for notification system
        # Could be email, SMS, webhook, etc.
        self.logger.info(f"Notification sent for alert: {alert.message}")
    
    def get_alerts(self, severity: Optional[str] = None, 
                  acknowledged: Optional[bool] = None,
                  hours: int = 24) -> List[Dict]:
        """Get alerts with filters"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            filtered_alerts = []
            for alert in self.alerts:
                # Time filter
                if alert.timestamp < cutoff_time:
                    continue
                
                # Severity filter
                if severity and alert.severity != severity:
                    continue
                
                # Acknowledged filter
                if acknowledged is not None and alert.acknowledged != acknowledged:
                    continue
                
                filtered_alerts.append({
                    "id": alert.id,
                    "timestamp": alert.timestamp.isoformat(),
                    "type": alert.type,
                    "severity": alert.severity,
                    "message": alert.message,
                    "details": alert.details,
                    "acknowledged": alert.acknowledged,
                    "resolved": alert.resolved
                })
            
            return filtered_alerts
            
        except Exception as e:
            self.logger.error(f"Get alerts error: {e}")
            return []
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert"""
        try:
            for alert in self.alerts:
                if alert.id == alert_id:
                    alert.acknowledged = True
                    self._save_alerts()
                    return True
            return False
        except Exception as e:
            self.logger.error(f"Acknowledge alert error: {e}")
            return False
    
    def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an alert"""
        try:
            for alert in self.alerts:
                if alert.id == alert_id:
                    alert.resolved = True
                    self._save_alerts()
                    return True
            return False
        except Exception as e:
            self.logger.error(f"Resolve alert error: {e}")
            return False
    
    def get_alert_statistics(self) -> Dict:
        """Get alert statistics"""
        try:
            now = datetime.now()
            last_24h = now - timedelta(hours=24)
            last_hour = now - timedelta(hours=1)
            
            recent_alerts = [a for a in self.alerts if a.timestamp >= last_24h]
            hourly_alerts = [a for a in self.alerts if a.timestamp >= last_hour]
            
            severity_counts = {}
            type_counts = {}
            
            for alert in recent_alerts:
                severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1
                type_counts[alert.type] = type_counts.get(alert.type, 0) + 1
            
            return {
                "total_alerts": len(self.alerts),
                "alerts_24h": len(recent_alerts),
                "alerts_1h": len(hourly_alerts),
                "unacknowledged": len([a for a in self.alerts if not a.acknowledged]),
                "unresolved": len([a for a in self.alerts if not a.resolved]),
                "severity_distribution": severity_counts,
                "type_distribution": type_counts
            }
            
        except Exception as e:
            self.logger.error(f"Alert statistics error: {e}")
            return {"error": str(e)}
    
    def enable_alert_rule(self, rule_name: str):
        """Enable alert rule"""
        if rule_name in self.alert_rules:
            self.alert_rules[rule_name].enabled = True
            self.logger.info(f"Enabled alert rule: {rule_name}")
    
    def disable_alert_rule(self, rule_name: str):
        """Disable alert rule"""
        if rule_name in self.alert_rules:
            self.alert_rules[rule_name].enabled = False
            self.logger.info(f"Disabled alert rule: {rule_name}")
    
    def get_alert_rules(self) -> Dict:
        """Get alert rules"""
        return {
            name: {
                "name": rule.name,
                "severity": rule.severity,
                "enabled": rule.enabled,
                "check_interval": rule.check_interval
            }
            for name, rule in self.alert_rules.items()
        }

monitoring_alerts = MonitoringAlerts() 