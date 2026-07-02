"""
Incident and Alert Models
Core data structures for Hybrid IDS alerts
"""

from enum import Enum
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import hashlib
import uuid


class AlertStatus(Enum):
    """Alert lifecycle states"""
    CREATED = "created"
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    ARCHIVED = "archived"


class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AttackCategory(Enum):
    """Attack categorization"""
    NETWORK_ONLY = "Network Only"
    HOST_ONLY = "Host Only"
    HYBRID = "Hybrid"
    MULTI_STAGE = "Multi-Stage"
    RECONNAISSANCE = "Reconnaissance"
    CREDENTIAL_ATTACK = "Credential Attack"
    LATERAL_MOVEMENT = "Lateral Movement"
    DATA_EXFILTRATION = "Data Exfiltration"
    UNKNOWN = "Unknown"


class DecisionType(Enum):
    """Fusion decision types"""
    NORMAL = "Normal"
    SUSPICIOUS = "Suspicious"
    CONFIRMED_INTRUSION = "Confirmed Intrusion"
    HYBRID_ATTACK = "Hybrid Attack"
    UNKNOWN_ATTACK = "Unknown Attack"


@dataclass
class NetworkEvidence:
    """Network-based detection evidence"""
    source_ip: str
    destination_ip: str
    protocol: str
    flow_id: str
    packet_count: int
    byte_count: int
    duration: float
    attack_type: str
    confidence: float
    binary_score: float
    unique_ports: int
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    port_entropy: float = 0.0
    packet_rate: float = 0.0
    byte_rate: float = 0.0
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class HostEvidence:
    """Host-based detection evidence"""
    session_id: str
    source_ip: str
    username: str
    hostname: str
    failed_attempts: int
    successful_attempts: int
    attack_type: str
    confidence: float
    host_score: float
    unique_users: int
    event_count: int
    duration: float
    timestamp: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


class Incident:
    """Complete incident representation"""
    
    def __init__(self):
        self.incident_id = self._generate_incident_id()
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        self.status = AlertStatus.CREATED
        
        # Detection data
        self.nids_detection: Optional[Dict] = None
        self.hids_detection: Optional[Dict] = None
        
        # Evidence
        self.network_evidence: Optional[NetworkEvidence] = None
        self.host_evidence: Optional[HostEvidence] = None
        
        # Correlation
        self.correlation_score = 0.0
        self.is_correlated = False
        self.correlation_reasons: List[str] = []
        
        # Decision
        self.decision = DecisionType.NORMAL
        self.attack_category = AttackCategory.UNKNOWN
        self.attack_type = "Unknown"
        self.confidence = 0.0
        self.severity = AlertSeverity.LOW
        
        # Impact
        self.source_ips: set = set()
        self.destination_ips: set = set()
        self.usernames: set = set()
        self.affected_hosts: set = set()
        
        # Timeline
        self.timeline: List[Dict] = []
        
        # Reasoning
        self.reasoning: List[str] = []
        self.evidence_summary: Dict = {}
        
        # Threat intelligence
        self.mitre_techniques: List[str] = []
        self.threat_description = ""
        self.recommended_actions: List[str] = []
        
        # Metadata
        self.acknowledged_by: Optional[str] = None
        self.acknowledged_at: Optional[datetime] = None
        self.resolved_by: Optional[str] = None
        self.resolved_at: Optional[datetime] = None
        self.notes: List[Dict] = []
    
    def _generate_incident_id(self) -> str:
        """Generate unique incident ID"""
        return f"INC-{uuid.uuid4().hex[:12].upper()}"
    
    def add_timeline_event(self, event_type: str, description: str, 
                          timestamp: Optional[datetime] = None):
        """Add event to incident timeline"""
        if timestamp is None:
            timestamp = datetime.utcnow()
        
        self.timeline.append({
            "timestamp": timestamp.isoformat(),
            "type": event_type,
            "description": description
        })
        
        self.updated_at = datetime.utcnow()
    
    def add_reasoning(self, reason: str):
        """Add reasoning for decision"""
        if reason not in self.reasoning:
            self.reasoning.append(reason)
    
    def acknowledge(self, analyst: str):
        """Acknowledge incident"""
        self.status = AlertStatus.ACKNOWLEDGED
        self.acknowledged_by = analyst
        self.acknowledged_at = datetime.utcnow()
        self.add_timeline_event(
            "acknowledged",
            f"Incident acknowledged by {analyst}"
        )
    
    def resolve(self, analyst: str):
        """Resolve incident"""
        self.status = AlertStatus.RESOLVED
        self.resolved_by = analyst
        self.resolved_at = datetime.utcnow()
        self.add_timeline_event(
            "resolved",
            f"Incident resolved by {analyst}"
        )
    
    def add_note(self, analyst: str, note: str):
        """Add analyst note"""
        self.notes.append({
            "analyst": analyst,
            "timestamp": datetime.utcnow().isoformat(),
            "note": note
        })
    
    def to_dict(self) -> Dict:
        """Convert incident to dictionary"""
        return {
            "incident_id": self.incident_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "status": self.status.value,
            "decision": self.decision.value,
            "attack_category": self.attack_category.value,
            "attack_type": self.attack_type,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 4),
            "source_ips": list(self.source_ips),
            "destination_ips": list(self.destination_ips),
            "usernames": list(self.usernames),
            "affected_hosts": list(self.affected_hosts),
            "nids_detection": self.nids_detection,
            "hids_detection": self.hids_detection,
            "network_evidence": self.network_evidence.to_dict() if self.network_evidence else None,
            "host_evidence": self.host_evidence.to_dict() if self.host_evidence else None,
            "correlation_score": round(self.correlation_score, 4),
            "is_correlated": self.is_correlated,
            "timeline": self.timeline,
            "reasoning": self.reasoning,
            "evidence_summary": self.evidence_summary,
            "mitre_techniques": self.mitre_techniques,
            "threat_description": self.threat_description,
            "recommended_actions": self.recommended_actions,
            "acknowledged_by": self.acknowledged_by,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "resolved_by": self.resolved_by,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "notes": self.notes
        }