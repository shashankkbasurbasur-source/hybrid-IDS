"""
Fusion Decision Engine
Makes final decision on incident classification
"""

from typing import Dict, List, Optional
from backend.models.incident import (
    Incident, DecisionType, AlertSeverity, AttackCategory
)
from backend.detection.severity_engine import SeverityEngine


class DecisionEngine:
    """Makes final decision on incident classification"""
    
    def __init__(self):
        self.severity_engine = SeverityEngine()
        
        # Decision thresholds
        self.confirmed_intrusion_threshold = 0.75
        self.suspicious_threshold = 0.40
    
    def make_decision(self, incident: Incident) -> Incident:
        """
        Make final decision on incident
        
        Args:
            incident: Incident object with correlation data
        
        Returns:
            Incident with decision and severity set
        """
        
        # Collect evidence
        network_score = 0.0
        host_score = 0.0
        
        if incident.nids_detection:
            network_score = incident.nids_detection.get("score", 0.0)
        
        if incident.hids_detection:
            host_score = incident.hids_detection.get("host_score", 0.0)
        
        # Calculate final confidence
        confidence = self._calculate_confidence(incident, network_score, host_score)
        incident.confidence = confidence
        
        # Make decision
        if incident.is_correlated and confidence >= self.confirmed_intrusion_threshold:
            incident.decision = DecisionType.CONFIRMED_INTRUSION
        elif network_score >= self.confirmed_intrusion_threshold or \
             host_score >= self.confirmed_intrusion_threshold:
            incident.decision = DecisionType.CONFIRMED_INTRUSION
        elif confidence >= self.suspicious_threshold:
            incident.decision = DecisionType.SUSPICIOUS
        else:
            incident.decision = DecisionType.NORMAL
        
        # Calculate severity
        incident_dict = incident.to_dict()
        incident_dict["confidence"] = confidence
        severity = self.severity_engine.calculate_severity(incident_dict)
        incident.severity = severity
        
        incident.add_timeline_event(
            "decision_made",
            f"Decision: {incident.decision.value}, Severity: {severity.value}"
        )
        
        return incident
    
    def _calculate_confidence(self, incident: Incident, 
                            network_score: float, 
                            host_score: float) -> float:
        """
        Calculate final confidence score
        
        Combines multiple evidence sources
        """
        
        confidence = 0.0
        evidence_count = 0
        
        # Network evidence weight (60%)
        if incident.nids_detection:
            network_weight = 0.6
            nids_confidence = incident.nids_detection.get("confidence", 0.0)
            confidence += nids_confidence * network_weight
            evidence_count += 1
        
        # Host evidence weight (40%)
        if incident.hids_detection:
            host_weight = 0.4
            hids_confidence = incident.hids_detection.get("confidence", 0.0)
            confidence += hids_confidence * host_weight
            evidence_count += 1
        
        # Correlation boost
        if incident.is_correlated:
            correlation_weight = incident.correlation_score * 0.15
            confidence += correlation_weight
        
        # Ensure confidence is between 0 and 1
        return min(max(confidence, 0.0), 1.0)
    
    def add_reasoning(self, incident: Incident, score: float, 
                     decision: DecisionType):
        """Add reasoning for decision"""
        
        if decision == DecisionType.CONFIRMED_INTRUSION:
            incident.add_reasoning(
                f"High confidence detection (score: {score:.2%})"
            )
        elif decision == DecisionType.SUSPICIOUS:
            incident.add_reasoning(
                f"Medium confidence detection (score: {score:.2%})"
            )
        else:
            incident.add_reasoning(
                f"Low confidence detection (score: {score:.2%})"
            )