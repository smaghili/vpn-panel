import time
import json
import logging
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from fastapi import Request, HTTPException, status
import redis

@dataclass
class RateLimitConfig:
    """Configuration for rate limiting"""
    max_requests: int
    window_seconds: int
    block_duration: int = 0  # 0 means no blocking, just rate limiting

class RateLimiter:
    """Rate limiting implementation using Redis"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis_client = redis.from_url(redis_url)
        self.logger = logging.getLogger(__name__)
        
        # Default rate limit configurations
        self.default_limits = {
            "login": RateLimitConfig(max_requests=5, window_seconds=900, block_duration=1800),  # 5 attempts per 15min, block 30min
            "api": RateLimitConfig(max_requests=1000, window_seconds=3600),  # 1000 requests per hour
            "file_upload": RateLimitConfig(max_requests=10, window_seconds=86400),  # 10 files per day
            "user_creation": RateLimitConfig(max_requests=5, window_seconds=3600),  # 5 users per hour
            "config_download": RateLimitConfig(max_requests=50, window_seconds=3600),  # 50 downloads per hour
            "admin_actions": RateLimitConfig(max_requests=100, window_seconds=3600),  # 100 admin actions per hour
        }
    
    def _get_client_identifier(self, request: Request) -> str:
        """Get unique identifier for client (IP + User Agent)"""
        client_ip = request.client.host
        user_agent = request.headers.get("user-agent", "")
        return f"{client_ip}:{hash(user_agent)}"
    
    def _get_user_identifier(self, user_id: str) -> str:
        """Get unique identifier for user"""
        return f"user:{user_id}"
    
    def _get_rate_limit_key(self, identifier: str, limit_type: str) -> str:
        """Generate Redis key for rate limiting"""
        return f"rate_limit:{limit_type}:{identifier}"
    
    def _get_block_key(self, identifier: str, limit_type: str) -> str:
        """Generate Redis key for blocking"""
        return f"block:{limit_type}:{identifier}"
    
    def is_blocked(self, identifier: str, limit_type: str) -> bool:
        """Check if client/user is blocked"""
        block_key = self._get_block_key(identifier, limit_type)
        return bool(self.redis_client.exists(block_key))
    
    def get_remaining_requests(self, identifier: str, limit_type: str) -> Tuple[int, int]:
        """Get remaining requests and reset time"""
        config = self.default_limits.get(limit_type)
        if not config:
            return 999999, 0
        
        key = self._get_rate_limit_key(identifier, limit_type)
        current_time = int(time.time())
        window_start = current_time - config.window_seconds
        
        # Get requests in current window
        requests = self.redis_client.zrangebyscore(key, window_start, current_time)
        remaining = max(0, config.max_requests - len(requests))
        
        # Calculate reset time
        if requests:
            oldest_request = min(int(req) for req in requests)
            reset_time = oldest_request + config.window_seconds
        else:
            reset_time = current_time + config.window_seconds
        
        return remaining, reset_time
    
    def check_rate_limit(self, identifier: str, limit_type: str) -> Tuple[bool, Dict]:
        """Check if request is allowed"""
        config = self.default_limits.get(limit_type)
        if not config:
            return True, {"remaining": 999999, "reset_time": 0}
        
        # Check if blocked
        if self.is_blocked(identifier, limit_type):
            block_key = self._get_block_key(identifier, limit_type)
            block_until = self.redis_client.get(block_key)
            if block_until:
                block_until = int(block_until)
                if time.time() < block_until:
                    remaining_block = block_until - int(time.time())
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail={
                            "error": "Rate limit exceeded",
                            "blocked_until": block_until,
                            "remaining_block_seconds": remaining_block,
                            "limit_type": limit_type
                        }
                    )
                else:
                    # Unblock if time expired
                    self.redis_client.delete(block_key)
        
        # Check rate limit
        remaining, reset_time = self.get_remaining_requests(identifier, limit_type)
        
        if remaining <= 0:
            # Rate limit exceeded
            if config.block_duration > 0:
                # Block the client/user
                block_key = self._get_block_key(identifier, limit_type)
                block_until = int(time.time()) + config.block_duration
                self.redis_client.setex(block_key, config.block_duration, block_until)
                
                self.logger.warning(f"Rate limit exceeded and blocked: {identifier}, type: {limit_type}")
                
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": "Rate limit exceeded - blocked",
                        "blocked_until": block_until,
                        "block_duration": config.block_duration,
                        "limit_type": limit_type
                    }
                )
            else:
                # Just rate limit, no blocking
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": "Rate limit exceeded",
                        "reset_time": reset_time,
                        "limit_type": limit_type
                    }
                )
        
        # Record the request
        key = self._get_rate_limit_key(identifier, limit_type)
        current_time = int(time.time())
        self.redis_client.zadd(key, {str(current_time): current_time})
        self.redis_client.expire(key, config.window_seconds)
        
        return True, {
            "remaining": remaining - 1,
            "reset_time": reset_time,
            "limit_type": limit_type
        }
    
    def check_client_rate_limit(self, request: Request, limit_type: str) -> Dict:
        """Check rate limit for client (IP-based)"""
        identifier = self._get_client_identifier(request)
        return self.check_rate_limit(identifier, limit_type)
    
    def check_user_rate_limit(self, user_id: str, limit_type: str) -> Dict:
        """Check rate limit for user (user-based)"""
        identifier = self._get_user_identifier(user_id)
        return self.check_rate_limit(identifier, limit_type)
    
    def update_rate_limit_config(self, limit_type: str, config: RateLimitConfig):
        """Update rate limit configuration"""
        self.default_limits[limit_type] = config
        self.logger.info(f"Updated rate limit config for {limit_type}: {config}")
    
    def get_rate_limit_stats(self, identifier: str, limit_type: str) -> Dict:
        """Get rate limit statistics"""
        config = self.default_limits.get(limit_type)
        if not config:
            return {"error": "Unknown limit type"}
        
        remaining, reset_time = self.get_remaining_requests(identifier, limit_type)
        is_blocked = self.is_blocked(identifier, limit_type)
        
        return {
            "limit_type": limit_type,
            "max_requests": config.max_requests,
            "window_seconds": config.window_seconds,
            "remaining_requests": remaining,
            "reset_time": reset_time,
            "is_blocked": is_blocked,
            "block_duration": config.block_duration
        }
    
    def reset_rate_limit(self, identifier: str, limit_type: str):
        """Reset rate limit for identifier"""
        key = self._get_rate_limit_key(identifier, limit_type)
        block_key = self._get_block_key(identifier, limit_type)
        
        self.redis_client.delete(key)
        self.redis_client.delete(block_key)
        
        self.logger.info(f"Reset rate limit for {identifier}, type: {limit_type}")
    
    def get_all_rate_limit_stats(self) -> Dict:
        """Get statistics for all rate limit types"""
        stats = {}
        for limit_type in self.default_limits.keys():
            stats[limit_type] = {
                "config": self.default_limits[limit_type],
                "active_blocks": self._count_active_blocks(limit_type),
                "active_limits": self._count_active_limits(limit_type)
            }
        return stats
    
    def _count_active_blocks(self, limit_type: str) -> int:
        """Count active blocks for limit type"""
        pattern = f"block:{limit_type}:*"
        return len(self.redis_client.keys(pattern))
    
    def _count_active_limits(self, limit_type: str) -> int:
        """Count active rate limits for limit type"""
        pattern = f"rate_limit:{limit_type}:*"
        return len(self.redis_client.keys(pattern))

# Global rate limiter instance
rate_limiter = RateLimiter() 