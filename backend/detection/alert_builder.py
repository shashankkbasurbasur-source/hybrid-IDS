"""
Alert Builder
Constructs complete alerts from incidents
"""

from datetime import datetime
from typing import Dict, Optional
from backend.models.incident import Incident, AlertStatus
from backend.detection.mitre_mapper import MitreMapper
from backend.storage.nids_store import nids_db


class AlertBuilder:
    """Builds complete alerts from incidents"""
    
    def __init__(self):
        self.mitre_mapper = MitreMapper()
        self.recommended_actions_map = self._load_recommended_actions()
    
    def _load_recommended_actions(self) -> Dict:
        """Load recommended actions by attack type"""
        return {
            "Port Scan": [
                "Review firewall rules",
                "Enable port-based alerting",
                "Identify scanning source"
            ],
            "SSH Brute Force": [
                "Check failed login patterns",
                "Review SSH logs on target",
                "Consider blocking source IP",
                "Enable SSH key authentication"
            ],
            "DoS": [
                "Verify DDoS mitigation in place",
                "Contact ISP if needed",
                "Monitor bandwidth usage"
            ],
            "Privilege Escalation": [
                "Immediately investigate target host",
                "Check for unauthorized access",
                "Review sudo/elevation logs",
                "Quarantine affected host if needed"
            ],
            "Unauthorized Access": [
                "Reset affected credentials",
                "Investigate host for compromise",
                "Review file modifications",
                "Monitor for lateral movement"
            ]
        }
    
    def build_alert(self, incident: Incident) -> Dict:
        """
        Build complete alert from incident
        
        Returns: Complete alert dictionary
        """
        
        # Enrich with MITRE mapping
        incident_dict = incident.to_dict()
        mitre_mapping = self.mitre_mapper.map_incident(incident_dict)
        incident.mitre_techniques = mitre_mapping.get("techniques", [])
        incident.threat_description = mitre_mapping.get("description", "")
        
        # Add recommended actions
        attack_type = incident.attack_type
        incident.recommended_actions = self.recommended_actions_map.get(
            attack_type,
            ["Investigate and respond appropriately"]
        )
        
        # Build evidence summary
        incident.evidence_summary = self._build_evidence_summary(incident)
        
        # Store in database
        alert_id = nids_db.insert_alert(incident_dict)
        
        # Return complete alert
        return incident.to_dict()
    
    def _build_evidence_summary(self, incident: Incident) -> Dict:
        """Build summary of supporting evidence"""
        
        summary = {
            "network": {},
            "host": {},
            "correlation": {}
        }
        
        # Network evidence
        if incident.nids_detection:
            nids = incident.nids_detection
            summary["network"] = {
                "source_ip": nids.get("src_ip"),
                "destination_ip": nids.get("dst_ip"),
                "attack_type": nids.get("attack_type"),
                "confidence": nids.get("confidence"),
                "flow_id": nids.get("flow_id"),
                "packets": nids.get("packet_count"),
                "bytes": nids.get("byte_count")
            }
        
        # Host evidence
        if incident.hids_detection:
            hids = incident.hids_detection
            summary["host"] = {
                "source_ip": hids.get("source_ip"),
                "username": hids.get("username"),
                "attack_type": hids.get("attack_type"),
                "confidence": hids.get("confidence"),
                "failed_attempts": hids.get("failed_attempts"),
                "successful_attempts": hids.get("successful_attempts")
            }
        
        # Correlation
        if incident.is_correlated:
            summary["correlation"] = {
                "is_correlated": True,
                "score": incident.correlation_score,
                "reasons": incident.correlation_reasons
            }
        
        return summary