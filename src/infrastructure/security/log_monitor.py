import os
import re
import json
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from pathlib import Path
import subprocess
import psutil

@dataclass
class SecurityEvent:
    timestamp: datetime
    event_type: str
    severity: str
    source: str
    message: str
    details: Dict
    ip_address: Optional[str] = None
    user_id: Optional[str] = None

@dataclass
class AlertRule:
    name: str
    pattern: str
    severity: str
    threshold: int
    time_window: int
    action: str
    enabled: bool = True

class LogMonitor:
    def __init__(self, log_dir: str = "/var/log/vpn-panel"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)
        
        self.security_events: List[SecurityEvent] = []
        self.alert_rules: Dict[str, AlertRule] = {}
        self.event_counters: Dict[str, int] = {}
        self.blocked_ips: Set[str] = set()
        self.suspicious_activities: Dict[str, List[datetime]] = {}
        
        self._init_alert_rules()
        self._init_log_files()
    
    def _init_log_files(self):
        """Initialize log files"""
        log_files = {
            "security": self.log_dir / "security.log",
            "access": self.log_dir / "access.log",
            "error": self.log_dir / "error.log",
            "audit": self.log_dir / "audit.log"
        }
        
        for log_file in log_files.values():
            if not log_file.exists():
                log_file.touch(mode=0o600)
    
    def _init_alert_rules(self):
        """Initialize security alert rules"""
        self.alert_rules = {
            "failed_login": AlertRule(
                name="Failed Login Attempts",
                pattern=r"Failed login attempt for user (.+) from IP (.+)",
                severity="high",
                threshold=5,
                time_window=300,
                action="block_ip"
            ),
            "rate_limit_exceeded": AlertRule(
                name="Rate Limit Exceeded",
                pattern=r"Rate limit exceeded for IP (.+)",
                severity="medium",
                threshold=10,
                time_window=600,
                action="block_ip"
            ),
            "suspicious_activity": AlertRule(
                name="Suspicious Activity",
                pattern=r"Suspicious activity detected from IP (.+)",
                severity="high",
                threshold=3,
                time_window=1800,
                action="block_ip"
            ),
            "admin_action": AlertRule(
                name="Admin Actions",
                pattern=r"Admin action performed by user (.+)",
                severity="low",
                threshold=50,
                time_window=3600,
                action="log_only"
            ),
            "backup_creation": AlertRule(
                name="Backup Creation",
                pattern=r"Backup created by user (.+)",
                severity="info",
                threshold=10,
                time_window=3600,
                action="log_only"
            ),
            "system_error": AlertRule(
                name="System Errors",
                pattern=r"System error occurred",
                severity="medium",
                threshold=5,
                time_window=300,
                action="alert_admin"
            )
        }
    
    def log_security_event(self, event_type: str, severity: str, source: str, 
                          message: str, details: Dict, ip_address: Optional[str] = None,
                          user_id: Optional[str] = None):
        """Log a security event"""
        event = SecurityEvent(
            timestamp=datetime.now(),
            event_type=event_type,
            severity=severity,
            source=source,
            message=message,
            details=details,
            ip_address=ip_address,
            user_id=user_id
        )
        
        self.security_events.append(event)
        
        # Write to security log
        log_entry = {
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type,
            "severity": event.severity,
            "source": event.source,
            "message": event.message,
            "details": event.details,
            "ip_address": event.ip_address,
            "user_id": event.user_id
        }
        
        with open(self.log_dir / "security.log", "a") as f:
            f.write(json.dumps(log_entry) + "\n")
        
        # Check for alerts
        self._check_alerts(event)
        
        # Clean old events
        self._cleanup_old_events()
    
    def _check_alerts(self, event: SecurityEvent):
        """Check if event triggers any alerts"""
        for rule_name, rule in self.alert_rules.items():
            if not rule.enabled:
                continue
            
            if re.search(rule.pattern, event.message):
                self._increment_counter(rule_name, event.ip_address)
                
                if self._should_trigger_alert(rule_name, event.ip_address):
                    self._trigger_alert(rule, event)
    
    def _increment_counter(self, rule_name: str, ip_address: Optional[str] = None):
        """Increment event counter"""
        key = f"{rule_name}:{ip_address}" if ip_address else rule_name
        self.event_counters[key] = self.event_counters.get(key, 0) + 1
    
    def _should_trigger_alert(self, rule_name: str, ip_address: Optional[str] = None) -> bool:
        """Check if alert should be triggered"""
        rule = self.alert_rules[rule_name]
        key = f"{rule_name}:{ip_address}" if ip_address else rule_name
        count = self.event_counters.get(key, 0)
        
        return count >= rule.threshold
    
    def _trigger_alert(self, rule: AlertRule, event: SecurityEvent):
        """Trigger security alert"""
        alert_message = f"ALERT: {rule.name} - {event.message}"
        
        if rule.action == "block_ip" and event.ip_address:
            self._block_ip(event.ip_address, rule.name)
        elif rule.action == "alert_admin":
            self._send_admin_alert(alert_message, event)
        
        # Log alert
        self.logger.warning(alert_message)
        
        # Write to audit log
        audit_entry = {
            "timestamp": datetime.now().isoformat(),
            "alert_type": rule.name,
            "severity": rule.severity,
            "action": rule.action,
            "message": alert_message,
            "ip_address": event.ip_address,
            "user_id": event.user_id
        }
        
        with open(self.log_dir / "audit.log", "a") as f:
            f.write(json.dumps(audit_entry) + "\n")
    
    def _block_ip(self, ip_address: str, reason: str):
        """Block IP address using iptables"""
        try:
            # Check if IP is already blocked
            if ip_address in self.blocked_ips:
                return
            
            # Add iptables rule
            subprocess.run([
                "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"
            ], check=True)
            
            self.blocked_ips.add(ip_address)
            self.logger.info(f"Blocked IP {ip_address} due to {reason}")
            
            # Log blocking action
            self.log_security_event(
                "ip_blocked",
                "high",
                "firewall",
                f"IP {ip_address} blocked due to {reason}",
                {"reason": reason, "ip": ip_address},
                ip_address=ip_address
            )
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to block IP {ip_address}: {e}")
    
    def _send_admin_alert(self, message: str, event: SecurityEvent):
        """Send alert to admin (placeholder for future implementation)"""
        # This could be implemented with email, SMS, or webhook
        self.logger.critical(f"ADMIN ALERT: {message}")
        
        # For now, just log it
        alert_entry = {
            "timestamp": datetime.now().isoformat(),
            "type": "admin_alert",
            "message": message,
            "event": {
                "type": event.event_type,
                "severity": event.severity,
                "source": event.source,
                "ip_address": event.ip_address,
                "user_id": event.user_id
            }
        }
        
        with open(self.log_dir / "alerts.log", "a") as f:
            f.write(json.dumps(alert_entry) + "\n")
    
    def _cleanup_old_events(self):
        """Clean up old events and counters"""
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        # Clean security events
        self.security_events = [
            event for event in self.security_events 
            if event.timestamp > cutoff_time
        ]
        
        # Clean suspicious activities
        for ip, activities in self.suspicious_activities.items():
            self.suspicious_activities[ip] = [
                activity for activity in activities 
                if activity > cutoff_time
            ]
    
    def get_security_stats(self) -> Dict:
        """Get security statistics"""
        now = datetime.now()
        last_24h = now - timedelta(hours=24)
        last_hour = now - timedelta(hours=1)
        
        recent_events = [
            event for event in self.security_events 
            if event.timestamp > last_24h
        ]
        
        hourly_events = [
            event for event in self.security_events 
            if event.timestamp > last_hour
        ]
        
        severity_counts = {}
        event_type_counts = {}
        
        for event in recent_events:
            severity_counts[event.severity] = severity_counts.get(event.severity, 0) + 1
            event_type_counts[event.event_type] = event_type_counts.get(event.event_type, 0) + 1
        
        return {
            "total_events_24h": len(recent_events),
            "total_events_1h": len(hourly_events),
            "blocked_ips": len(self.blocked_ips),
            "severity_distribution": severity_counts,
            "event_type_distribution": event_type_counts,
            "suspicious_activities": len(self.suspicious_activities),
            "active_counters": len(self.event_counters)
        }
    
    def get_recent_events(self, hours: int = 24) -> List[Dict]:
        """Get recent security events"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        recent_events = [
            event for event in self.security_events 
            if event.timestamp > cutoff_time
        ]
        
        return [
            {
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type,
                "severity": event.severity,
                "source": event.source,
                "message": event.message,
                "ip_address": event.ip_address,
                "user_id": event.user_id
            }
            for event in recent_events
        ]
    
    def unblock_ip(self, ip_address: str) -> bool:
        """Unblock IP address"""
        try:
            if ip_address not in self.blocked_ips:
                return False
            
            # Remove iptables rule
            subprocess.run([
                "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"
            ], check=True)
            
            self.blocked_ips.remove(ip_address)
            self.logger.info(f"Unblocked IP {ip_address}")
            
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to unblock IP {ip_address}: {e}")
            return False
    
    def get_blocked_ips(self) -> List[str]:
        """Get list of blocked IP addresses"""
        return list(self.blocked_ips)
    
    def add_alert_rule(self, rule: AlertRule):
        """Add new alert rule"""
        self.alert_rules[rule.name.lower().replace(" ", "_")] = rule
        self.logger.info(f"Added alert rule: {rule.name}")
    
    def update_alert_rule(self, rule_name: str, **kwargs):
        """Update existing alert rule"""
        if rule_name in self.alert_rules:
            rule = self.alert_rules[rule_name]
            for key, value in kwargs.items():
                if hasattr(rule, key):
                    setattr(rule, key, value)
            self.logger.info(f"Updated alert rule: {rule_name}")
    
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
    
    def get_alert_rules(self) -> Dict[str, Dict]:
        """Get all alert rules"""
        return {
            name: {
                "name": rule.name,
                "pattern": rule.pattern,
                "severity": rule.severity,
                "threshold": rule.threshold,
                "time_window": rule.time_window,
                "action": rule.action,
                "enabled": rule.enabled
            }
            for name, rule in self.alert_rules.items()
        }

log_monitor = LogMonitor() 