import time
from collections import defaultdict
from fastapi import Request, HTTPException, status
from typing import Dict, Tuple

class RateLimiter:
    def __init__(self, requests_per_minute: int = 60, requests_per_hour: int = 1000):
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self.minute_requests = defaultdict(list)
        self.hour_requests = defaultdict(list)
    
    def get_client_ip(self, request: Request) -> str:
        """Extract client IP from request"""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host
    
    def is_rate_limited(self, client_ip: str) -> Tuple[bool, str]:
        """Check if client is rate limited"""
        current_time = time.time()
        
        # Clean old requests
        self._clean_old_requests(client_ip, current_time)
        
        # Check minute limit
        if len(self.minute_requests[client_ip]) >= self.requests_per_minute:
            return True, "Rate limit exceeded: too many requests per minute"
        
        # Check hour limit
        if len(self.hour_requests[client_ip]) >= self.requests_per_hour:
            return True, "Rate limit exceeded: too many requests per hour"
        
        # Add current request
        self.minute_requests[client_ip].append(current_time)
        self.hour_requests[client_ip].append(current_time)
        
        return False, ""
    
    def _clean_old_requests(self, client_ip: str, current_time: float):
        """Remove old requests from tracking"""
        # Clean minute requests (older than 60 seconds)
        self.minute_requests[client_ip] = [
            req_time for req_time in self.minute_requests[client_ip]
            if current_time - req_time < 60
        ]
        
        # Clean hour requests (older than 3600 seconds)
        self.hour_requests[client_ip] = [
            req_time for req_time in self.hour_requests[client_ip]
            if current_time - req_time < 3600
        ] 