import redis
import json
import pickle
from typing import Any, Optional, Union
from datetime import timedelta
import logging

class RedisCache:
    def __init__(self, host: str = 'localhost', port: int = 6379, db: int = 0, 
                 password: Optional[str] = None, decode_responses: bool = True):
        self.redis_client = redis.Redis(
            host=host,
            port=port,
            db=db,
            password=password,
            decode_responses=decode_responses
        )
        self.logger = logging.getLogger(__name__)
    
    def set(self, key: str, value: Any, expire: Optional[Union[int, timedelta]] = None) -> bool:
        """Set a key-value pair in cache"""
        try:
            if isinstance(value, (dict, list)):
                serialized_value = json.dumps(value)
            else:
                serialized_value = str(value)
            
            if isinstance(expire, timedelta):
                expire = int(expire.total_seconds())
            
            return self.redis_client.set(key, serialized_value, ex=expire)
        except Exception as e:
            self.logger.error(f"Error setting cache key {key}: {e}")
            return False
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a value from cache"""
        try:
            value = self.redis_client.get(key)
            if value is None:
                return default
            
            # Try to deserialize JSON
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value
        except Exception as e:
            self.logger.error(f"Error getting cache key {key}: {e}")
            return default
    
    def delete(self, key: str) -> bool:
        """Delete a key from cache"""
        try:
            return bool(self.redis_client.delete(key))
        except Exception as e:
            self.logger.error(f"Error deleting cache key {key}: {e}")
            return False
    
    def exists(self, key: str) -> bool:
        """Check if a key exists in cache"""
        try:
            return bool(self.redis_client.exists(key))
        except Exception as e:
            self.logger.error(f"Error checking cache key {key}: {e}")
            return False
    
    def expire(self, key: str, expire: Union[int, timedelta]) -> bool:
        """Set expiration for a key"""
        try:
            if isinstance(expire, timedelta):
                expire = int(expire.total_seconds())
            return bool(self.redis_client.expire(key, expire))
        except Exception as e:
            self.logger.error(f"Error setting expiration for cache key {key}: {e}")
            return False
    
    def ttl(self, key: str) -> int:
        """Get time to live for a key"""
        try:
            return self.redis_client.ttl(key)
        except Exception as e:
            self.logger.error(f"Error getting TTL for cache key {key}: {e}")
            return -1
    
    def clear_pattern(self, pattern: str) -> int:
        """Clear all keys matching a pattern"""
        try:
            keys = self.redis_client.keys(pattern)
            if keys:
                return self.redis_client.delete(*keys)
            return 0
        except Exception as e:
            self.logger.error(f"Error clearing cache pattern {pattern}: {e}")
            return 0
    
    def clear_all(self) -> bool:
        """Clear all cache"""
        try:
            self.redis_client.flushdb()
            return True
        except Exception as e:
            self.logger.error(f"Error clearing all cache: {e}")
            return False
    
    def get_stats(self) -> dict:
        """Get cache statistics"""
        try:
            info = self.redis_client.info()
            return {
                "total_keys": info.get("db0", {}).get("keys", 0),
                "memory_usage": info.get("used_memory_human", "0B"),
                "connected_clients": info.get("connected_clients", 0),
                "uptime": info.get("uptime_in_seconds", 0)
            }
        except Exception as e:
            self.logger.error(f"Error getting cache stats: {e}")
            return {}

class CacheManager:
    def __init__(self, redis_cache: RedisCache):
        self.cache = redis_cache
        self.logger = logging.getLogger(__name__)
    
    def cache_user_data(self, user_id: str, user_data: dict, expire: timedelta = timedelta(hours=1)):
        """Cache user data"""
        key = f"user:{user_id}"
        return self.cache.set(key, user_data, expire)
    
    def get_cached_user_data(self, user_id: str) -> Optional[dict]:
        """Get cached user data"""
        key = f"user:{user_id}"
        return self.cache.get(key)
    
    def invalidate_user_cache(self, user_id: str):
        """Invalidate user cache"""
        key = f"user:{user_id}"
        return self.cache.delete(key)
    
    def cache_server_list(self, user_id: str, servers: list, expire: timedelta = timedelta(minutes=5)):
        """Cache server list for user"""
        key = f"servers:{user_id}"
        return self.cache.set(key, servers, expire)
    
    def get_cached_server_list(self, user_id: str) -> Optional[list]:
        """Get cached server list for user"""
        key = f"servers:{user_id}"
        return self.cache.get(key)
    
    def cache_client_list(self, user_id: str, clients: list, expire: timedelta = timedelta(minutes=5)):
        """Cache client list for user"""
        key = f"clients:{user_id}"
        return self.cache.set(key, clients, expire)
    
    def get_cached_client_list(self, user_id: str) -> Optional[list]:
        """Get cached client list for user"""
        key = f"clients:{user_id}"
        return self.cache.get(key)
    
    def cache_dashboard_stats(self, stats: dict, expire: timedelta = timedelta(minutes=2)):
        """Cache dashboard statistics"""
        key = "dashboard:stats"
        return self.cache.set(key, stats, expire)
    
    def get_cached_dashboard_stats(self) -> Optional[dict]:
        """Get cached dashboard statistics"""
        key = "dashboard:stats"
        return self.cache.get(key)
    
    def invalidate_all_user_cache(self, user_id: str):
        """Invalidate all cache for a user"""
        patterns = [f"user:{user_id}", f"servers:{user_id}", f"clients:{user_id}"]
        for pattern in patterns:
            self.cache.clear_pattern(pattern)
    
    def invalidate_server_cache(self):
        """Invalidate all server-related cache"""
        return self.cache.clear_pattern("servers:*")
    
    def invalidate_client_cache(self):
        """Invalidate all client-related cache"""
        return self.cache.clear_pattern("clients:*")
    
    def invalidate_dashboard_cache(self):
        """Invalidate dashboard cache"""
        return self.cache.delete("dashboard:stats") 