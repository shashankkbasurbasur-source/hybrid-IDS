"""
Threat Reporter
Generates comprehensive threat analysis reports
"""

from typing import Dict, Optional
from datetime import datetime
from backend.intelligence.threat_knowledge_base import ThreatKnowledgeBase
from backend.intelligence.stage_identifier import AttackStageIdentifier
from backend.intelligence.ioc_generator import IOCGenerator
from backend.intelligence.risk_assessor import RiskAssessor
from typing import Optional, Dict, List


class ThreatReporter:
    """Generates threat analysis reports"""
    
    def __init__(self):
        self.knowledge_base = ThreatKnowledgeBase()
        self.stage_identifier = AttackStageIdentifier()
        self.ioc_generator = IOCGenerator()
        self.risk_assessor = RiskAssessor()
    
    def generate_report(self, alert: Dict) -> Dict:
        """
        Generate complete threat analysis report
        
        Returns:
            Comprehensive threat report
        """
        
        attack_type = alert.get("attack_type", "Unknown")
        confidence = alert.get("confidence", 0.0)
        
        report = {
            "report_id": self._generate_report_id(),
            "timestamp": datetime.utcnow().isoformat(),
            "alert_id": alert.get("incident_id"),
            
            # Attack identification
            "attack": self._build_attack_section(alert),
            
            # Evidence analysis
            "evidence": self._build_evidence_section(alert),
            
            # Attack stage
            "lifecycle": self._build_lifecycle_section(alert),
            
            # Indicators
            "iocs": self._build_iocs_section(alert),
            
            # Risk assessment
            "risk": self._build_risk_section(alert),
            
            # Threat description
            "threat_analysis": self._build_threat_analysis(alert),
            
            # Response recommendations
            "response": self._build_response_section(alert),
            
            # Investigation guidance
            "investigation": self._build_investigation_section(alert),
            
            # Confidence assessment
            "confidence_assessment": self._build_confidence_assessment(alert)
        }
        
        return report
    
    def _build_attack_section(self, alert: Dict) -> Dict:
        """Build attack identification section"""
        
        attack_type = alert.get("attack_type", "Unknown")
        knowledge = self.knowledge_base.get_knowledge(attack_type)
        mitre_info = self.knowledge_base.get_mitre_info(attack_type)
        
        attack_section = {
            "type": attack_type,
            "description": knowledge.get("description", "Unknown attack") if knowledge else "Unknown attack",
            "category": alert.get("attack_category", "Unknown"),
            "mitre": mitre_info if mitre_info else {},
            "severity": alert.get("severity", "UNKNOWN"),
            "decision": alert.get("decision", "Unknown")
        }
        
        if knowledge:
            attack_section.update({
                "objectives": knowledge.get("objectives", []),
                "methodology": knowledge.get("methodology", []),
                "affected_services": knowledge.get("affected_services", [])
            })
        
        return attack_section
    
    def _build_evidence_section(self, alert: Dict) -> Dict:
        """Build evidence supporting the detection"""
        
        evidence = {
            "network_detection": {},
            "host_detection": {},
            "correlation": {}
        }
        
        nids_det = alert.get("nids_detection")
        if nids_det:
            evidence["network_detection"] = {
                "type": "Network Intrusion Detection System",
                "attack_type": nids_det.get("attack_type"),
                "confidence": nids_det.get("confidence"),
                "source_ip": nids_det.get("src_ip"),
                "destination_ip": nids_det.get("dst_ip"),
                "protocol": nids_det.get("protocol"),
                "packet_count": nids_det.get("packet_count"),
                "byte_count": nids_det.get("byte_count"),
                "flow_id": nids_det.get("flow_id")
            }
        
        hids_det = alert.get("hids_detection")
        if hids_det:
            evidence["host_detection"] = {
                "type": "Host Intrusion Detection System",
                "attack_type": hids_det.get("attack_type"),
                "confidence": hids_det.get("confidence"),
                "source_ip": hids_det.get("source_ip"),
                "username": hids_det.get("username"),
                "failed_attempts": hids_det.get("failed_attempts"),
                "successful_attempts": hids_det.get("successful_attempts"),
                "session_id": hids_det.get("session_id")
            }
        
        if alert.get("is_correlated"):
            evidence["correlation"] = {
                "is_correlated": True,
                "correlation_score": alert.get("correlation_score"),
                "correlation_type": "Temporal and source IP match",
                "reasons": alert.get("correlation_reasons", [])
            }
        
        return evidence
    
    def _build_lifecycle_section(self, alert: Dict) -> Dict:
        """Build attack lifecycle section"""
        
        stage = self.stage_identifier.identify_stage(alert)
        next_stage = self.stage_identifier.get_next_likely_stage(stage)
        
        return {
            "current_stage": stage.value,
            "stage_description": self.stage_identifier.get_stage_description(stage),
            "next_likely_stage": next_stage.value if next_stage else None,
            "attack_progression": self._build_progression(alert)
        }
    
    def _build_iocs_section(self, alert: Dict) -> Dict:
        """Build IOCs section"""
        
        iocs = self.ioc_generator.extract_iocs(alert)
        
        return {
            "network": iocs.get("network", []),
            "host": iocs.get("host", []),
            "file": iocs.get("file", []),
            "process": iocs.get("process", []),
            "searchable_iocs": self._build_searchable_iocs(iocs)
        }
    
    def _build_risk_section(self, alert: Dict) -> Dict:
        """Build risk assessment section"""
        
        risk_assessment = self.risk_assessor.assess_risk(alert)
        
        return {
            "business_risk": risk_assessment.get("business_risk", {}),
            "operational_risk": risk_assessment.get("operational_risk", {}),
            "asset_impact": risk_assessment.get("asset_impact", {}),
            "overall_risk": risk_assessment.get("overall_risk", {})
        }
    
    def _build_threat_analysis(self, alert: Dict) -> Dict:
        """Build detailed threat analysis"""
        
        attack_type = alert.get("attack_type", "Unknown")
        knowledge = self.knowledge_base.get_knowledge(attack_type)
        
        if not knowledge:
            return {
                "status": "UNKNOWN_ATTACK",
                "description": "Attack type not in threat database",
                "evidence_summary": self._summarize_evidence(alert),
                "investigation_required": True
            }
        
        return {
            "status": "KNOWN_ATTACK",
            "description": knowledge.get("description"),
            "objectives": knowledge.get("objectives", []),
            "methodology": knowledge.get("methodology", []),
            "indicators": knowledge.get("indicators", []),
            "affected_services": knowledge.get("affected_services", []),
            "references": knowledge.get("references", [])
        }
    
    def _build_response_section(self, alert: Dict) -> Dict:
        """Build response recommendations"""
        
        attack_type = alert.get("attack_type", "Unknown")
        knowledge = self.knowledge_base.get_knowledge(attack_type)
        
        if not knowledge:
            return {
                "recommended_actions": [
                    "Investigate alert thoroughly",
                    "Collect additional evidence",
                    "Review system logs",
                    "Monitor for escalation"
                ]
            }
        
        response = knowledge.get("response", {})
        
        return {
            "immediate_actions": response.get("immediate", []),
            "short_term_actions": response.get("short_term", []),
            "long_term_actions": response.get("long_term", []),
            "prevention_measures": knowledge.get("prevention", [])
        }
    
    def _build_investigation_section(self, alert: Dict) -> Dict:
        """Build investigation guidance"""
        
        investigation = {
            "next_steps": [
                "Review alert evidence",
                "Check for related incidents",
                "Investigate affected systems",
                "Review access logs",
                "Monitor for indicators"
            ],
            "key_questions": self._generate_key_questions(alert),
            "evidence_to_collect": self._generate_evidence_collection_guide(alert),
            "containment_actions": self._generate_containment_actions(alert)
        }
        
        return investigation
    
    def _build_confidence_assessment(self, alert: Dict) -> Dict:
        """Build confidence assessment"""
        
        confidence = alert.get("confidence")
        if confidence is None:
            confidence = 0.0
        
        if confidence >= 0.8:
            confidence_level = "High"
            recommendation = "Treat as confirmed threat"
        elif confidence >= 0.6:
            confidence_level = "Medium"
            recommendation = "Investigate promptly"
        elif confidence >= 0.4:
            confidence_level = "Low-Medium"
            recommendation = "Investigate when possible"
        else:
            confidence_level = "Low"
            recommendation = "Possible false positive - verify before taking action"
        
        return {
            "confidence_score": round(confidence, 4),
            "confidence_level": confidence_level,
            "supporting_evidence": alert.get("reasoning", []),
            "recommendation": recommendation,
            "false_positive_risk": "High" if confidence < 0.4 else "Low"
        }
    
    def _generate_report_id(self) -> str:
        """Generate unique report ID"""
        import uuid
        return f"TR-{uuid.uuid4().hex[:12].upper()}"
    
    def _summarize_evidence(self, alert: Dict) -> str:
        """Summarize available evidence"""
        
        summary = []
        
        if alert.get("nids_detection"):
            summary.append("Network-based detection")
        
        if alert.get("hids_detection"):
            summary.append("Host-based detection")
        
        if alert.get("is_correlated"):
            summary.append("Correlated detection")
        
        return " and ".join(summary) if summary else "Limited evidence"
    
    def _build_progression(self, alert: Dict) -> List[str]:
        """Build attack progression chain"""
        
        # This would track a multi-stage attack progression
        progression = ["Initial Detection"]
        
        if alert.get("nids_detection"):
            progression.append("Network Activity Detected")
        
        if alert.get("hids_detection"):
            progression.append("Host Activity Detected")
        
        if alert.get("is_correlated"):
            progression.append("Coordinated Attack Pattern")
        
        return progression
    
    def _build_searchable_iocs(self, iocs: Dict) -> List[str]:
        """Build list of searchable IOCs"""
        
        searchable = []
        
        for category, ioc_list in iocs.items():
            for ioc in ioc_list:
                searchable.append(ioc.get("value", ""))
        
        return [ioc for ioc in searchable if ioc]
    
    def _generate_key_questions(self, alert: Dict) -> List[str]:
        """Generate key investigation questions"""
        
        attack_type = alert.get("attack_type", "Unknown")
        
        questions = [
            "Is this attack ongoing or has it concluded?",
            "What is the source of the attack?",
            "Are there multiple attack phases visible?",
            "Has the attacker gained system access?"
        ]
        
        if "Brute Force" in attack_type:
            questions.extend([
                "Which accounts were targeted?",
                "Were any accounts successfully compromised?",
                "Are there signs of post-compromise activity?"
            ])
        
        elif "Privilege" in attack_type:
            questions.extend([
                "Has root/administrator access been gained?",
                "What privileged commands were executed?",
                "Are there signs of persistence mechanisms?"
            ])
        
        return questions
    
    def _generate_evidence_collection_guide(self, alert: Dict) -> Dict:
        """Generate evidence collection guide"""
        
        return {
            "network": [
                "Packet capture from the time of attack",
                "Firewall logs",
                "IDS/IPS alerts",
                "NetFlow data"
            ],
            "host": [
                "Authentication logs",
                "System logs",
                "Command history",
                "Process execution logs",
                "File access logs"
            ],
            "immediate": [
                "Preserve volatile data",
                "Snapshot system memory if needed",
                "Secure access logs"
            ]
        }
    
    def _generate_containment_actions(self, alert: Dict) -> List[str]:
        """Generate containment actions"""
        
        severity = alert.get("severity", "LOW")
        attack_type = alert.get("attack_type", "Unknown")
        
        containment = []
        
        if severity in ["CRITICAL", "HIGH"]:
            containment.append("Prepare to isolate affected system")
            containment.append("Block attacker IP at firewall")
        
        if "Brute Force" in attack_type:
            containment.append("Force password reset on targeted accounts")
            containment.append("Disable or lock targeted accounts")
        
        elif "Privilege" in attack_type:
            containment.append("Immediately isolate affected system")
            containment.append("Plan full system rebuild")
        
        containment.append("Increase monitoring and alerting")
        
        return containment