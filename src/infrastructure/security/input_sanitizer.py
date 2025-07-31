import re
import html
from typing import Any, Dict, List, Union
from urllib.parse import quote, unquote

class InputSanitizer:
    def __init__(self):
        self.sql_patterns = [
            r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|OR|AND)\b)',
            r'(\b(script|javascript|vbscript|expression)\b)',
            r'([;\'\"\\])',
            r'(\b(union|select|insert|update|delete|drop|create|alter|exec)\b)'
        ]
        
        self.xss_patterns = [
            r'<script[^>]*>.*?</script>',
            r'<iframe[^>]*>.*?</iframe>',
            r'<object[^>]*>.*?</object>',
            r'<embed[^>]*>.*?</embed>',
            r'javascript:',
            r'vbscript:',
            r'onload=',
            r'onerror=',
            r'onclick='
        ]
    
    def sanitize_string(self, value: str, max_length: int = 255) -> str:
        """Sanitize a string input"""
        if not isinstance(value, str):
            return str(value)
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # HTML escape
        value = html.escape(value)
        
        # Remove SQL injection patterns
        for pattern in self.sql_patterns:
            value = re.sub(pattern, '', value, flags=re.IGNORECASE)
        
        # Remove XSS patterns
        for pattern in self.xss_patterns:
            value = re.sub(pattern, '', value, flags=re.IGNORECASE)
        
        # Trim and limit length
        value = value.strip()
        if len(value) > max_length:
            value = value[:max_length]
        
        return value
    
        # Email functionality removed - no longer needed
    
    def sanitize_url(self, url: str) -> str:
        """Sanitize URL input"""
        if not url:
            return ""
        
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Basic URL validation
        url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        if not re.match(url_pattern, url):
            raise ValueError("Invalid URL format")
        
        return url
    
    def sanitize_integer(self, value: Any, min_val: int = None, max_val: int = None) -> int:
        """Sanitize integer input"""
        try:
            int_value = int(value)
            
            if min_val is not None and int_value < min_val:
                raise ValueError(f"Value must be at least {min_val}")
            
            if max_val is not None and int_value > max_val:
                raise ValueError(f"Value must be at most {max_val}")
            
            return int_value
        except (ValueError, TypeError):
            raise ValueError("Invalid integer value")
    
    def sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize dictionary input"""
        sanitized = {}
        
        for key, value in data.items():
            if isinstance(value, str):
                sanitized[key] = self.sanitize_string(value)
            elif isinstance(value, dict):
                sanitized[key] = self.sanitize_dict(value)
            elif isinstance(value, list):
                sanitized[key] = self.sanitize_list(value)
            else:
                sanitized[key] = value
        
        return sanitized
    
    def sanitize_list(self, data: List[Any]) -> List[Any]:
        """Sanitize list input"""
        sanitized = []
        
        for item in data:
            if isinstance(item, str):
                sanitized.append(self.sanitize_string(item))
            elif isinstance(item, dict):
                sanitized.append(self.sanitize_dict(item))
            elif isinstance(item, list):
                sanitized.append(self.sanitize_list(item))
            else:
                sanitized.append(item)
        
        return sanitized 