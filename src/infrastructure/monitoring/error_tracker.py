import traceback
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from collections import defaultdict, deque

@dataclass
class ErrorEvent:
    timestamp: datetime
    error_type: str
    error_message: str
    stack_trace: str
    user_id: Optional[str]
    username: Optional[str]
    ip_address: str
    user_agent: str
    request_path: str
    request_method: str
    request_data: Dict[str, Any]
    severity: str  # low, medium, high, critical

class ErrorTracker:
    def __init__(self, max_errors: int = 1000):
        self.max_errors = max_errors
        self.errors = deque(maxlen=max_errors)
        self.error_counts = defaultdict(int)
        self.severity_levels = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        
        # Setup error logger
        self.logger = self._setup_error_logger()
    
    def _setup_error_logger(self) -> logging.Logger:
        """Setup error logger"""
        logger = logging.getLogger('error_tracker')
        logger.setLevel(logging.ERROR)
        
        # Create file handler
        file_handler = logging.FileHandler('/var/log/vpn-panel/errors.log')
        file_handler.setLevel(logging.ERROR)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        
        # Add handler to logger
        logger.addHandler(file_handler)
        
        return logger
    
    def track_error(self, error: Exception, request: Any = None, 
                   user_id: str = None, username: str = None,
                   severity: str = 'medium'):
        """Track an error event"""
        try:
            # Extract error information
            error_type = type(error).__name__
            error_message = str(error)
            stack_trace = traceback.format_exc()
            
            # Extract request information
            ip_address = "unknown"
            user_agent = "unknown"
            request_path = "unknown"
            request_method = "unknown"
            request_data = {}
            
            if request:
                ip_address = self._get_client_ip(request)
                user_agent = request.headers.get("User-Agent", "unknown")
                request_path = request.url.path
                request_method = request.method
                request_data = self._extract_request_data(request)
            
            # Create error event
            error_event = ErrorEvent(
                timestamp=datetime.now(),
                error_type=error_type,
                error_message=error_message,
                stack_trace=stack_trace,
                user_id=user_id,
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,
                request_path=request_path,
                request_method=request_method,
                request_data=request_data,
                severity=severity
            )
            
            # Store error
            self.errors.append(error_event)
            self.error_counts[error_type] += 1
            
            # Log error
            self._log_error(error_event)
            
        except Exception as e:
            # Fallback logging if error tracking fails
            logging.error(f"Failed to track error: {e}")
    
    def _get_client_ip(self, request: Any) -> str:
        """Extract client IP from request"""
        try:
            forwarded = request.headers.get("X-Forwarded-For")
            if forwarded:
                return forwarded.split(",")[0].strip()
            return request.client.host
        except:
            return "unknown"
    
    def _extract_request_data(self, request: Any) -> Dict[str, Any]:
        """Extract relevant request data"""
        try:
            data = {
                "headers": dict(request.headers),
                "query_params": dict(request.query_params),
                "path_params": dict(request.path_params)
            }
            
            # Remove sensitive information
            sensitive_headers = ['authorization', 'cookie', 'x-api-key']
            for header in sensitive_headers:
                if header in data["headers"]:
                    data["headers"][header] = "[REDACTED]"
            
            return data
        except:
            return {}
    
    def _log_error(self, error_event: ErrorEvent):
        """Log error to file"""
        try:
            error_dict = asdict(error_event)
            error_dict['timestamp'] = error_event.timestamp.isoformat()
            
            log_entry = {
                'type': 'error_event',
                'data': error_dict
            }
            
            self.logger.error(f"Error tracked: {error_event.error_type} - {error_event.error_message}")
            
        except Exception as e:
            logging.error(f"Failed to log error: {e}")
    
    def get_recent_errors(self, hours: int = 24) -> List[ErrorEvent]:
        """Get recent errors from the last N hours"""
        cutoff_time = datetime.now().replace(hour=datetime.now().hour - hours)
        return [e for e in self.errors if e.timestamp >= cutoff_time]
    
    def get_errors_by_type(self, error_type: str) -> List[ErrorEvent]:
        """Get all errors of a specific type"""
        return [e for e in self.errors if e.error_type == error_type]
    
    def get_errors_by_severity(self, severity: str) -> List[ErrorEvent]:
        """Get all errors of a specific severity"""
        return [e for e in self.errors if e.severity == severity]
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get error summary statistics"""
        if not self.errors:
            return {
                "total_errors": 0,
                "error_types": {},
                "severity_distribution": {},
                "recent_errors": []
            }
        
        # Error type distribution
        error_types = defaultdict(int)
        severity_distribution = defaultdict(int)
        
        for error in self.errors:
            error_types[error.error_type] += 1
            severity_distribution[error.severity] += 1
        
        # Recent errors (last 10)
        recent_errors = list(self.errors)[-10:]
        
        return {
            "total_errors": len(self.errors),
            "error_types": dict(error_types),
            "severity_distribution": dict(severity_distribution),
            "recent_errors": [
                {
                    "timestamp": e.timestamp.isoformat(),
                    "type": e.error_type,
                    "message": e.error_message,
                    "severity": e.severity,
                    "path": e.request_path
                }
                for e in recent_errors
            ]
        }
    
    def get_critical_errors(self) -> List[ErrorEvent]:
        """Get all critical errors"""
        return self.get_errors_by_severity('critical')
    
    def clear_old_errors(self, days: int = 7):
        """Clear errors older than specified days"""
        cutoff_time = datetime.now().replace(day=datetime.now().day - days)
        self.errors = deque(
            [e for e in self.errors if e.timestamp >= cutoff_time],
            maxlen=self.max_errors
        ) 