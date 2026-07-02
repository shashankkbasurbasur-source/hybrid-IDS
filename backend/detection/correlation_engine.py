"""
Correlation Engine
Correlates NIDS and HIDS detections
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from backend.models.incident import (
    Incident, NetworkEvidence, HostEvidence, AttackCategory, DecisionType
)


class CorrelationEngine:
    """Correlates network and host detections"""
    
    # Correlation window in seconds
    CORRELATION_WINDOW = 60  # 1 minute
    
    def __init__(self):
        self.pending_detections: Dict[str, Dict] = {}
        self.correlation_rules = self._load_correlation_rules()
    
    def _load_correlation_rules(self) -> Dict:
        """Load correlation rules"""
        return {
            "port_scan_to_brute_force": {
                "nids_attack": "Port Scan",
                "hids_attack": "SSH Brute Force",
                "time_gap": 120,  # 2 minutes
                "category": AttackCategory.MULTI_STAGE,
                "description": "Port scan followed by brute force attempt"
            },
            "dos_to_privilege_escalation": {
                "nids_attack": "DoS",
                "hids_attack": "Privilege Escalation",
                "time_gap": 180,
                "category": AttackCategory.MULTI_STAGE,
                "description": "DoS followed by privilege escalation"
            },
            "network_recon_to_host_attack": {
                "nids_attack": "Reconnaissance",
                "hids_attack": "SSH Brute Force",
                "time_gap": 300,  # 5 minutes
                "category": AttackCategory.HYBRID,
                "description": "Network reconnaissance leading to host attack"
            }
        }
    
    def correlate(self, nids_detection: Optional[Dict], 
                 hids_detection: Optional[Dict]) -> Incident:
        """
        Correlate NIDS and HIDS detections
        
        Returns: Incident object
        """
        
        incident = Incident()
        incident.add_timeline_event("started", "Correlation process started")
        
        # Store detections
        if nids_detection:
            incident.nids_detection = nids_detection
            incident.source_ips.add(nids_detection.get("src_ip", "unknown"))
            incident.destination_ips.add(nids_detection.get("dst_ip", "unknown"))
            incident.add_timeline_event(
                "nids_detection",
                f"NIDS detected {nids_detection.get('attack_type', 'Unknown')}"
            )
        
        if hids_detection:
            incident.hids_detection = hids_detection
            incident.source_ips.add(hids_detection.get("source_ip", "unknown"))
            incident.usernames.add(hids_detection.get("username", "unknown"))
            incident.add_timeline_event(
                "hids_detection",
                f"HIDS detected {hids_detection.get('attack_type', 'Unknown')}"
            )
        
        # Attempt correlation
        if nids_detection and hids_detection:
            self._correlate_detections(incident, nids_detection, hids_detection)
        elif nids_detection:
            self._classify_network_only(incident, nids_detection)
        elif hids_detection:
            self._classify_host_only(incident, hids_detection)
        
        incident.add_timeline_event("completed", "Correlation analysis completed")
        
        return incident
    
    def _correlate_detections(self, incident: Incident, 
                             nids_det: Dict, hids_det: Dict):
        """Correlate NIDS and HIDS detections"""
        
        # Check temporal correlation
        nids_time = datetime.fromisoformat(nids_det.get("timestamp", datetime.now().isoformat()))
        hids_time = datetime.fromisoformat(hids_det.get("timestamp", datetime.now().isoformat()))
        
        time_diff = abs((nids_time - hids_time).total_seconds())
        
        # Check source IP correlation
        nids_src = nids_det.get("src_ip", "")
        hids_src = hids_det.get("source_ip", "")
        
        ip_match = nids_src == hids_src
        
        # Calculate correlation score
        correlation_score = 0.0
        
        if time_diff <= self.CORRELATION_WINDOW:
            correlation_score += 0.4
            incident.add_reasoning(
                f"Temporal correlation: {time_diff:.0f}s apart"
            )
        
        if ip_match:
            correlation_score += 0.3
            incident.add_reasoning(f"Source IP correlation: {nids_src}")
        
        # Check attack pattern correlation
        attack_correlation = self._check_attack_pattern(nids_det, hids_det)
        if attack_correlation:
            correlation_score += 0.3
            incident.add_reasoning(attack_correlation["reason"])
            incident.attack_category = attack_correlation["category"]
        
        incident.correlation_score = correlation_score
        incident.is_correlated = correlation_score >= 0.5
        
        if incident.is_correlated:
            incident.decision = DecisionType.HYBRID_ATTACK
            incident.attack_category = AttackCategory.HYBRID
        else:
            incident.decision = DecisionType.SUSPICIOUS
    
    def _check_attack_pattern(self, nids_det: Dict, hids_det: Dict) -> Optional[Dict]:
        """Check for known attack patterns"""
        
        nids_attack = nids_det.get("attack_type", "")
        hids_attack = hids_det.get("attack_type", "")
        
        for rule_name, rule in self.correlation_rules.items():
            if (nids_attack == rule["nids_attack"] and 
                hids_attack == rule["hids_attack"]):
                return {
                    "rule": rule_name,
                    "reason": rule["description"],
                    "category": rule["category"]
                }
        
        return None
    
    def _classify_network_only(self, incident: Incident, nids_det: Dict):
        """Classify network-only attack"""
        
        incident.attack_category = AttackCategory.NETWORK_ONLY
        incident.attack_type = nids_det.get("attack_type", "Unknown")
        incident.confidence = nids_det.get("confidence", 0.0)
        
        nids_score = nids_det.get("score", 0.0)
        if nids_score >= 0.8:
            incident.decision = DecisionType.CONFIRMED_INTRUSION
        elif nids_score >= 0.5:
            incident.decision = DecisionType.SUSPICIOUS
        else:
            incident.decision = DecisionType.NORMAL
        
        incident.add_reasoning(
            f"Network-only detection: {nids_det.get('attack_type')}"
        )
    
    def _classify_host_only(self, incident: Incident, hids_det: Dict):
        """Classify host-only attack"""
        
        incident.attack_category = AttackCategory.HOST_ONLY
        incident.attack_type = hids_det.get("attack_type", "Unknown")
        incident.confidence = hids_det.get("confidence", 0.0)
        
        hids_score = hids_det.get("host_score", 0.0)
        if hids_score >= 0.8:
            incident.decision = DecisionType.CONFIRMED_INTRUSION
        elif hids_score >= 0.6:
            incident.decision = DecisionType.SUSPICIOUS
        else:
            incident.decision = DecisionType.NORMAL
        
        incident.add_reasoning(
            f"Host-only detection: {hids_det.get('attack_type')}"
        )