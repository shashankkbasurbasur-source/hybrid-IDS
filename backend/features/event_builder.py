"""
Authentication Event Builder
Groups related authentication events into sessions
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict
import hashlib


class AuthenticationSession:
    """Represents an authentication session from a source IP"""
    
    def __init__(self, source_ip: str):
        self.source_ip = source_ip
        self.events: List[Dict] = []
        self.start_time = datetime.now()
        self.last_event_time = self.start_time
        
        self.failed_attempts = 0
        self.successful_attempts = 0
        self.unique_users = set()
        self.unique_services = set()
        self.session_id = self._generate_id()
        self.status = "active"
    
    def _generate_id(self) -> str:
        """Generate unique session ID"""
        key = f"{self.source_ip}{self.start_time.isoformat()}"
        return hashlib.md5(key.encode()).hexdigest()[:12]
    
    def add_event(self, event: Dict):
        """Add authentication event to session"""
        
        self.events.append(event)
        self.last_event_time = datetime.fromisoformat(event["timestamp"])
        
        self.unique_users.add(event.get("user", "unknown"))
        self.unique_services.add(event.get("service", "ssh"))
        
        if event.get("success"):
            self.successful_attempts += 1
        else:
            self.failed_attempts += 1
    
    def get_duration(self) -> float:
        """Get session duration in seconds"""
        return (self.last_event_time - self.start_time).total_seconds()
    
    def is_active(self, timeout_sec: int = 60) -> bool:
        """Check if session is still active"""
        elapsed = (datetime.now() - self.last_event_time).total_seconds()
        return elapsed < timeout_sec
    
    def to_dict(self) -> Dict:
        """Convert session to dictionary"""
        return {
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "start_time": self.start_time.isoformat(),
            "end_time": self.last_event_time.isoformat(),
            "duration": self.get_duration(),
            "event_count": len(self.events),
            "failed_attempts": self.failed_attempts,
            "successful_attempts": self.successful_attempts,
            "unique_users": len(self.unique_users),
            "users": list(self.unique_users),
            "services": list(self.unique_services),
            "status": self.status
        }


class EventBuilder:
    """Builds authentication sessions from individual events"""
    
    def __init__(self, session_timeout: int = 60):
        self.sessions: Dict[str, AuthenticationSession] = {}
        self.session_timeout = session_timeout
        self.completed_sessions: List[AuthenticationSession] = []
        self.stats = {
            "sessions_created": 0,
            "sessions_completed": 0,
            "events_processed": 0
        }
    
    def add_event(self, event: Dict) -> Tuple[str, AuthenticationSession]:
        """
        Add event to session
        Returns: (session_id, session)
        """
        
        source_ip = event.get("source_ip", "unknown")
        
        # Create session if doesn't exist
        if source_ip not in self.sessions:
            self.sessions[source_ip] = AuthenticationSession(source_ip)
            self.stats["sessions_created"] += 1
        
        # Add event to session
        session = self.sessions[source_ip]
        session.add_event(event)
        self.stats["events_processed"] += 1
        
        return session.session_id, session
    
    def get_completed_sessions(self) -> List[AuthenticationSession]:
        """Get sessions that have timed out"""
        
        completed = []
        to_remove = []
        
        for source_ip, session in self.sessions.items():
            if not session.is_active(self.session_timeout):
                session.status = "completed"
                completed.append(session)
                to_remove.append(source_ip)
                self.stats["sessions_completed"] += 1
        
        # Remove completed sessions
        for ip in to_remove:
            del self.sessions[ip]
        
        return completed
    
    def get_active_sessions(self) -> Dict[str, Dict]:
        """Get currently active sessions"""
        return {
            session.session_id: session.to_dict()
            for session in self.sessions.values()
        }
    
    def get_stats(self) -> Dict:
        """Get builder statistics"""
        return {
            **self.stats,
            "sessions_active": len(self.sessions)
        }


from typing import Tuple