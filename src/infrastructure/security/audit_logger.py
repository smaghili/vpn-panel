import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict

@dataclass
class AuditEvent:
    timestamp: datetime
    user_id: str
    username: str
    action: str
    resource_type: str
    resource_id: str
    details: Dict[str, Any]
    ip_address: str
    user_agent: str
    success: bool
    error_message: Optional[str] = None

class AuditLogger:
    def __init__(self, log_file: str = "/var/log/vpn-panel/audit.log"):
        self.log_file = log_file
        self.logger = self._setup_logger()
    
    def _setup_logger(self) -> logging.Logger:
        """Setup audit logger"""
        logger = logging.getLogger('audit_logger')
        logger.setLevel(logging.INFO)
        
        # Create file handler
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        
        # Add handler to logger
        logger.addHandler(file_handler)
        
        return logger
    
    def log_event(self, event: AuditEvent):
        """Log an audit event"""
        try:
            event_dict = asdict(event)
            event_dict['timestamp'] = event.timestamp.isoformat()
            
            log_entry = {
                'type': 'audit_event',
                'data': event_dict
            }
            
            self.logger.info(json.dumps(log_entry))
        except Exception as e:
            # Fallback logging if audit logging fails
            logging.error(f"Failed to log audit event: {e}")
    
    def log_user_login(self, user_id: str, username: str, ip_address: str, 
                      user_agent: str, success: bool, error_message: str = None):
        """Log user login event"""
        event = AuditEvent(
            timestamp=datetime.now(),
            user_id=user_id,
            username=username,
            action="login",
            resource_type="user",
            resource_id=user_id,
            details={"login_method": "password"},
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            error_message=error_message
        )
        self.log_event(event)
    
    def log_user_logout(self, user_id: str, username: str, ip_address: str, 
                       user_agent: str):
        """Log user logout event"""
        event = AuditEvent(
            timestamp=datetime.now(),
            user_id=user_id,
            username=username,
            action="logout",
            resource_type="user",
            resource_id=user_id,
            details={},
            ip_address=ip_address,
            user_agent=user_agent,
            success=True
        )
        self.log_event(event)
    
    def log_resource_creation(self, user_id: str, username: str, resource_type: str,
                            resource_id: str, details: Dict[str, Any], ip_address: str,
                            user_agent: str):
        """Log resource creation event"""
        event = AuditEvent(
            timestamp=datetime.now(),
            user_id=user_id,
            username=username,
            action="create",
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            success=True
        )
        self.log_event(event)
    
    def log_resource_update(self, user_id: str, username: str, resource_type: str,
                          resource_id: str, details: Dict[str, Any], ip_address: str,
                          user_agent: str):
        """Log resource update event"""
        event = AuditEvent(
            timestamp=datetime.now(),
            user_id=user_id,
            username=username,
            action="update",
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            success=True
        )
        self.log_event(event)
    
    def log_resource_deletion(self, user_id: str, username: str, resource_type: str,
                            resource_id: str, details: Dict[str, Any], ip_address: str,
                            user_agent: str):
        """Log resource deletion event"""
        event = AuditEvent(
            timestamp=datetime.now(),
            user_id=user_id,
            username=username,
            action="delete",
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            success=True
        )
        self.log_event(event)
    
    def log_permission_denied(self, user_id: str, username: str, action: str,
                            resource_type: str, resource_id: str, ip_address: str,
                            user_agent: str):
        """Log permission denied event"""
        event = AuditEvent(
            timestamp=datetime.now(),
            user_id=user_id,
            username=username,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details={"reason": "permission_denied"},
            ip_address=ip_address,
            user_agent=user_agent,
            success=False,
            error_message="Permission denied"
        )
        self.log_event(event) 