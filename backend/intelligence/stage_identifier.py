"""
Attack Stage Identification
Determines lifecycle stage of attack
"""

from typing import Dict, Optional
from backend.intelligence.threat_knowledge_base import (
    ThreatKnowledgeBase, AttackStage
)


class AttackStageIdentifier:
    """Identifies attack lifecycle stage"""
    
    def __init__(self):
        self.knowledge_base = ThreatKnowledgeBase()
    
    def identify_stage(self, alert: Dict) -> AttackStage:
        """
        Identify attack stage from alert
        
        Returns: AttackStage enum
        """
        
        attack_type = alert.get("attack_type", "Unknown")
        
        # Get stage from knowledge base
        stage = self.knowledge_base.get_attack_stage(attack_type)
        if stage:
            return stage
        
        # Infer stage from evidence if not in knowledge base
        return self._infer_stage(alert)
    
    def _infer_stage(self, alert: Dict) -> AttackStage:
        """Infer attack stage from evidence"""
        
        # Check for initial reconnaissance indicators
        nids_det = alert.get("nids_detection", {})
        if nids_det.get("attack_type") in ["Port Scan", "Reconnaissance"]:
            return AttackStage.RECONNAISSANCE
        
        # Check for credential attack indicators
        hids_det = alert.get("hids_detection", {})
        if hids_det.get("attack_type") in ["SSH Brute Force", "Credential Stuffing"]:
            return AttackStage.CREDENTIAL_ACCESS
        
        # Check for access indicators
        if hids_det.get("successful_attempts", 0) > 0:
            return AttackStage.INITIAL_ACCESS
        
        # Check for denial of service
        if nids_det.get("attack_type") in ["DoS", "DDoS"]:
            return AttackStage.IMPACT
        
        # Default to unknown
        return AttackStage.RECONNAISSANCE
    
    def get_stage_description(self, stage: AttackStage) -> str:
        """Get human-readable stage description"""
        
        descriptions = {
            AttackStage.RECONNAISSANCE: "Attacker gathering information about the target",
            AttackStage.RESOURCE_DEVELOPMENT: "Attacker developing resources for the attack",
            AttackStage.INITIAL_ACCESS: "Attacker gaining initial access to the system",
            AttackStage.EXECUTION: "Attacker executing malicious code",
            AttackStage.PERSISTENCE: "Attacker establishing persistent access",
            AttackStage.PRIVILEGE_ESCALATION: "Attacker elevating system privileges",
            AttackStage.DEFENSE_EVASION: "Attacker avoiding detection",
            AttackStage.CREDENTIAL_ACCESS: "Attacker targeting credentials",
            AttackStage.DISCOVERY: "Attacker discovering system details",
            AttackStage.LATERAL_MOVEMENT: "Attacker moving within network",
            AttackStage.COLLECTION: "Attacker collecting data",
            AttackStage.COMMAND_CONTROL: "Attacker maintaining command and control",
            AttackStage.EXFILTRATION: "Attacker exfiltrating data",
            AttackStage.IMPACT: "Attacker impacting systems or data"
        }
        
        return descriptions.get(stage, "Unknown stage")
    
    def get_next_likely_stage(self, current_stage: AttackStage) -> Optional[AttackStage]:
        """Get next likely attack stage in progression"""
        
        stage_progression = {
            AttackStage.RECONNAISSANCE: AttackStage.INITIAL_ACCESS,
            AttackStage.INITIAL_ACCESS: AttackStage.CREDENTIAL_ACCESS,
            AttackStage.CREDENTIAL_ACCESS: AttackStage.EXECUTION,
            AttackStage.EXECUTION: AttackStage.PERSISTENCE,
            AttackStage.PERSISTENCE: AttackStage.PRIVILEGE_ESCALATION,
            AttackStage.PRIVILEGE_ESCALATION: AttackStage.LATERAL_MOVEMENT,
            AttackStage.LATERAL_MOVEMENT: AttackStage.COLLECTION,
            AttackStage.COLLECTION: AttackStage.EXFILTRATION,
            AttackStage.EXFILTRATION: AttackStage.IMPACT,
        }
        
        return stage_progression.get(current_stage)