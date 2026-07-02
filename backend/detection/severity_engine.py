"""
Centralized Severity Calculation
Single source of truth for severity assignment
"""

from typing import Dict
from backend.models.incident import AlertSeverity, AttackCategory


class SeverityEngine:
    """Calculates alert severity based on multiple factors"""
    
    def __init__(self):
        # Base severity by attack type
        self.attack_severity_map = {
            "Privilege Escalation": AlertSeverity.CRITICAL,
            "SSH Brute Force": AlertSeverity.HIGH,
            "Unauthorized Access": AlertSeverity.HIGH,
            "DoS": AlertSeverity.HIGH,
            "DDoS": AlertSeverity.CRITICAL,
            "Port Scan": AlertSeverity.MEDIUM,
            "Reconnaissance": AlertSeverity.MEDIUM,
            "Lateral Movement": AlertSeverity.HIGH,
            "Data Exfiltration": AlertSeverity.CRITICAL,
            "Credential Stuffing": AlertSeverity.MEDIUM,
            "Anomalous System Activity": AlertSeverity.MEDIUM,
            "Normal": AlertSeverity.LOW
        }
        
        # Category base severity
        self.category_severity_map = {
            AttackCategory.NETWORK_ONLY: AlertSeverity.MEDIUM,
            AttackCategory.HOST_ONLY: AlertSeverity.MEDIUM,
            AttackCategory.HYBRID: AlertSeverity.HIGH,
            AttackCategory.MULTI_STAGE: AlertSeverity.CRITICAL,
            AttackCategory.RECONNAISSANCE: AlertSeverity.MEDIUM,
            AttackCategory.CREDENTIAL_ATTACK: AlertSeverity.HIGH,
            AttackCategory.LATERAL_MOVEMENT: AlertSeverity.HIGH,
            AttackCategory.DATA_EXFILTRATION: AlertSeverity.CRITICAL,
            AttackCategory.UNKNOWN: AlertSeverity.LOW
        }
    
    def calculate_severity(self, incident: Dict) -> AlertSeverity:
        """
        Calculate incident severity
        
        Inputs:
            - Attack type
            - Attack category
            - Confidence
            - Evidence strength
            - Affected assets
        
        Returns: AlertSeverity
        """
        
        severity_score = 0.0
        
        # 1. Attack type base severity (40%)
        attack_type = incident.get("attack_type", "Unknown")
        base_severity = self.attack_severity_map.get(
            attack_type,
            AlertSeverity.MEDIUM
        )
        severity_score += self._severity_to_score(base_severity) * 0.4
        
        # 2. Category modifier (30%)
        category = incident.get("attack_category", AttackCategory.UNKNOWN)
        category_severity = self.category_severity_map.get(
            category,
            AlertSeverity.LOW
        )
        severity_score += self._severity_to_score(category_severity) * 0.3
        
        # 3. Confidence multiplier (20%)
        confidence = incident.get("confidence", 0.0)
        confidence_score = confidence * 100  # 0-100
        severity_score += (confidence_score / 100.0) * 0.2
        
        # 4. Evidence strength (10%)
        evidence_strength = self._calculate_evidence_strength(incident)
        severity_score += evidence_strength * 0.1
        
        # Convert score back to severity level
        final_severity = self._score_to_severity(severity_score)
        
        return final_severity
    
    def _severity_to_score(self, severity: AlertSeverity) -> float:
        """Convert severity enum to numeric score"""
        severity_scores = {
            AlertSeverity.LOW: 1.0,
            AlertSeverity.MEDIUM: 2.5,
            AlertSeverity.HIGH: 3.5,
            AlertSeverity.CRITICAL: 4.0
        }
        return severity_scores.get(severity, 1.0)
    
    def _score_to_severity(self, score: float) -> AlertSeverity:
        """Convert numeric score back to severity"""
        if score >= 3.5:
            return AlertSeverity.CRITICAL
        elif score >= 2.75:
            return AlertSeverity.HIGH
        elif score >= 1.75:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW
    
    def _calculate_evidence_strength(self, incident: Dict) -> float:
        """Calculate strength of supporting evidence"""
        
        strength = 0.0
        
        # Check for dual detection (strong evidence)
        if incident.get("nids_detection") and incident.get("hids_detection"):
            strength += 0.5
        
        # Check for correlation
        if incident.get("is_correlated"):
            strength += 0.3
        
        # Check for multiple affected hosts/users
        affected_assets = len(incident.get("affected_hosts", []))
        if affected_assets > 1:
            strength += 0.2
        
        return min(strength, 1.0)   