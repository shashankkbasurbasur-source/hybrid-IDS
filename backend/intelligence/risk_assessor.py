"""
Risk Assessment
Evaluates business and operational risk
"""

from typing import Dict
from enum import Enum


class RiskLevel(Enum):
    """Risk levels"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class RiskAssessor:
    """Assesses risk from threats"""
    
    def __init__(self):
        pass
    
    def assess_risk(self, alert: Dict) -> Dict:
        """
        Assess risk from alert
        
        Returns:
            Risk assessment with multiple dimensions
        """
        
        severity = alert.get("severity", "LOW")
        confidence = alert.get("confidence", 0.0)
        attack_type = alert.get("attack_type", "Unknown")
        
        # Business risk assessment
        business_risk = self._assess_business_risk(attack_type, severity, confidence)
        
        # Operational risk assessment
        operational_risk = self._assess_operational_risk(attack_type, severity)
        
        # Asset impact
        asset_impact = self._assess_asset_impact(alert)
        
        # Overall risk
        overall_risk = self._calculate_overall_risk(
            business_risk, operational_risk, asset_impact
        )
        
        return {
            "business_risk": {
                "level": business_risk["level"].value if isinstance(business_risk["level"], RiskLevel) else str(business_risk["level"]),
                "factors": business_risk["factors"],
                "impact": business_risk["impact"]
            },
            "operational_risk": {
                "level": operational_risk["level"].value if isinstance(operational_risk["level"], RiskLevel) else str(operational_risk["level"]),
                "factors": operational_risk["factors"]
            },
            "asset_impact": {
                "affected_assets": asset_impact["affected_assets"],
                "criticality": asset_impact["criticality"],
                "data_at_risk": asset_impact["data_at_risk"]
            },
            "overall_risk": {
                "level": overall_risk.value if isinstance(overall_risk, RiskLevel) else str(overall_risk),
                "score": self._risk_to_score(overall_risk),
                "priority": self._determine_priority(overall_risk, confidence)
            }
        }
    
    def _assess_business_risk(self, attack_type: str, 
                            severity: str, confidence: float) -> Dict:
        """Assess business impact"""
        
        # Attack-type-based business risk
        attack_business_risk = {
            "Port Scan": {
                "level": RiskLevel.MEDIUM,
                "factors": ["Reconnaissance precedes attacks"],
                "impact": "Preparation for targeted attack"
            },
            "SSH Brute Force": {
                "level": RiskLevel.HIGH,
                "factors": ["Credential compromise", "Unauthorized access"],
                "impact": "System access and potential data theft"
            },
            "DoS": {
                "level": RiskLevel.HIGH,
                "factors": ["Service disruption", "Revenue impact"],
                "impact": "Service unavailability"
            },
            "Privilege Escalation": {
                "level": RiskLevel.CRITICAL,
                "factors": ["Full system control", "Data compromise"],
                "impact": "Complete system compromise"
            },
            "Unauthorized Access": {
                "level": RiskLevel.HIGH,
                "factors": ["Active compromise", "Lateral movement risk"],
                "impact": "Insider threat, data theft, lateral movement"
            }
        }
        
        risk = attack_business_risk.get(
            attack_type,
            {
                "level": RiskLevel.MEDIUM,
                "factors": ["Unknown attack"],
                "impact": "Potential compromise"
            }
        )
        
        # Adjust based on confidence
        if confidence < 0.4:
            risk["level"] = self._downgrade_risk(risk["level"])
        
        return risk
    
    def _assess_operational_risk(self, attack_type: str, 
                                severity: str) -> Dict:
        """Assess operational impact"""
        
        operational_impacts = {
            "Port Scan": {
                "level": RiskLevel.LOW,
                "factors": ["Requires follow-up attack"]
            },
            "SSH Brute Force": {
                "level": RiskLevel.HIGH,
                "factors": ["Immediate credential compromise risk"]
            },
            "DoS": {
                "level": RiskLevel.CRITICAL,
                "factors": ["Active service disruption"]
            },
            "Privilege Escalation": {
                "level": RiskLevel.CRITICAL,
                "factors": ["Complete system compromise"]
            }
        }
        
        return operational_impacts.get(
            attack_type,
            {
                "level": RiskLevel.MEDIUM,
                "factors": ["Operational impact unclear"]
            }
        )
    
    def _assess_asset_impact(self, alert: Dict) -> Dict:
        """Assess impact on assets"""
        
        affected_assets = set()
        
        nids_det = alert.get("nids_detection", {})
        if nids_det:
            dst_ip = nids_det.get("dst_ip")
            if dst_ip:
                affected_assets.add(f"Host: {dst_ip}")
        
        hids_det = alert.get("hids_detection", {})
        if hids_det:
            hostname = hids_det.get("hostname")
            if hostname:
                affected_assets.add(f"System: {hostname}")
            
            username = hids_det.get("username")
            if username:
                affected_assets.add(f"User: {username}")
        
        # Determine data at risk
        data_at_risk = self._determine_data_at_risk(alert)
        
        return {
            "affected_assets": list(affected_assets),
            "criticality": "High" if len(affected_assets) > 1 else "Medium",
            "data_at_risk": data_at_risk
        }
    
    def _determine_data_at_risk(self, alert: Dict) -> str:
        """Determine what data is at risk"""
        
        attack_type = alert.get("attack_type", "Unknown")
        
        if attack_type in ["Privilege Escalation", "Unauthorized Access"]:
            return "All data on affected system"
        elif attack_type in ["SSH Brute Force"]:
            return "User credentials and accessible files"
        elif attack_type in ["DoS", "Port Scan"]:
            return "Service availability"
        else:
            return "Depends on attack success"
    
    def _calculate_overall_risk(self, business_risk: Dict, 
                               operational_risk: Dict,
                               asset_impact: Dict) -> RiskLevel:
        """Calculate overall risk"""
        
        # Get risk levels
        business = business_risk.get("level", RiskLevel.MEDIUM)
        operational = operational_risk.get("level", RiskLevel.MEDIUM)
        
        # Use maximum of the two
        if business in [RiskLevel.CRITICAL, operational in [RiskLevel.CRITICAL]]:
            return RiskLevel.CRITICAL
        elif business in [RiskLevel.HIGH, operational in [RiskLevel.HIGH]]:
            return RiskLevel.HIGH
        elif business in [RiskLevel.MEDIUM, operational in [RiskLevel.MEDIUM]]:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _downgrade_risk(self, risk_level: RiskLevel) -> RiskLevel:
        """Downgrade risk level"""
        
        downgrade_map = {
            RiskLevel.CRITICAL: RiskLevel.HIGH,
            RiskLevel.HIGH: RiskLevel.MEDIUM,
            RiskLevel.MEDIUM: RiskLevel.LOW,
            RiskLevel.LOW: RiskLevel.LOW
        }
        
        return downgrade_map.get(risk_level, RiskLevel.LOW)
    
    def _risk_to_score(self, risk_level: RiskLevel) -> int:
        """Convert risk level to numeric score"""
        
        scores = {
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4
        }
        
        return scores.get(risk_level, 0)
    
    def _determine_priority(self, risk_level: RiskLevel, 
                           confidence: float) -> str:
        """Determine investigation priority"""
        
        if risk_level == RiskLevel.CRITICAL or confidence > 0.9:
            return "CRITICAL - Investigate Immediately"
        elif risk_level == RiskLevel.HIGH or confidence > 0.7:
            return "HIGH - Investigate Soon"
        elif risk_level == RiskLevel.MEDIUM or confidence > 0.5:
            return "MEDIUM - Investigate When Possible"
        else:
            return "LOW - Monitor and Review"