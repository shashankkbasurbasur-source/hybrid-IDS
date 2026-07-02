"""
Cache Manager for Dashboard Data
Provides efficient caching with TTL
"""

from typing import Dict, Optional, Any
from datetime import datetime, timedelta
import threading


class CacheEntry:
    """Cache entry with TTL"""
    
    def __init__(self, data: Any, ttl_seconds: int = 5):
        self.data = data
        self.created_at = datetime.utcnow()
        self.ttl_seconds = ttl_seconds
    
    def is_expired(self) -> bool:
        """Check if cache entry has expired"""
        elapsed = (datetime.utcnow() - self.created_at).total_seconds()
        return elapsed > self.ttl_seconds


class DashboardCacheManager:
    """Manages dashboard data caching"""
    
    def __init__(self):
        self.cache: Dict[str, CacheEntry] = {}
        self.lock = threading.Lock()
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired"""
        with self.lock:
            if key in self.cache:
                entry = self.cache[key]
                if not entry.is_expired():
                    return entry.data
                else:
                    del self.cache[key]
        
        return None
    
    def set(self, key: str, data: Any, ttl_seconds: int = 5):
        """Set cache value with TTL"""
        with self.lock:
            self.cache[key] = CacheEntry(data, ttl_seconds)
    
    def invalidate(self, key: str):
        """Invalidate cache entry"""
        with self.lock:
            if key in self.cache:
                del self.cache[key]
    
    def clear(self):
        """Clear all cache"""
        with self.lock:
            self.cache.clear()
    
    def cleanup_expired(self):
        """Remove expired entries"""
        with self.lock:
            expired_keys = [
                key for key, entry in self.cache.items()
                if entry.is_expired()
            ]
            
            for key in expired_keys:
                del self.cache[key]


# Global instance
cache_manager = DashboardCacheManager()