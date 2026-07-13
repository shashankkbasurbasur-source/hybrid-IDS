"""
Cache Manager for Dashboard
Handles in-memory caching with TTL
"""

import time
from typing import Any, Optional, Dict


class CacheManager:
    """Simple in-memory cache with TTL support"""
    
    def __init__(self):
        self._cache: Dict[str, tuple] = {}  # {key: (value, expiry_time)}
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired"""
        if key not in self._cache:
            return None
        
        value, expiry_time = self._cache[key]
        
        # Check if expired
        if time.time() > expiry_time:
            del self._cache[key]
            return None
        
        return value
    
    def set(self, key: str, value: Any, ttl_seconds: int = 3600) -> None:
        """Set value in cache with TTL"""
        expiry_time = time.time() + ttl_seconds
        self._cache[key] = (value, expiry_time)
    
    def clear(self) -> None:
        """Clear all cache"""
        self._cache.clear()
    
    def cleanup(self) -> None:
        """Remove expired entries"""
        current_time = time.time()
        expired_keys = [
            key for key, (_, expiry) in self._cache.items() 
            if current_time > expiry
        ]
        for key in expired_keys:
            del self._cache[key]


# Global cache instance
cache_manager = CacheManager()
