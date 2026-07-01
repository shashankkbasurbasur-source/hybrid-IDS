"""
Structured Alert Generation
"""

from datetime import datetime
from typing import Dict, List
from backend.alerts.threat_intelligence import ThreatIntelligenceBase


def build_alert(
    decision: str,
    score: float,
    attack_type: str = "Unknown",
    domain: str = "Unknown",
    source_ip: str = "Unknown",
    destination_ip: str = "Unknown",
    severity_override: str = None
) -> Dict:
    """Build structured security alert"""
    
    if decision not in ["Intrusion", "Normal"]:
        raise ValueError("Invalid decision")
    
    # Determine severity
    if severity_override:
        severity = severity_override
    elif decision == "Normal":
        severity = "LOW"
    else:
        if score >= 0.85:
            severity = "CRITICAL"
        elif score >= 0.70:
            severity = "HIGH"
        elif score >= 0.40:
            severity = "MEDIUM"
        else:
            severity = "LOW"
    
    return {
        "id": datetime.utcnow().isoformat(),
        "timestamp": datetime.utcnow().isoformat(),
        "decision": decision,
        "score": round(score, 4),
        "attack_type": attack_type,
        "domain": domain,
        "severity": severity,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "confidence": round(score, 4),
        "source": "Hybrid IDS",
        "status": "Active" if decision == "Intrusion" else "Resolved"
    }


def enrich_alert_with_threat_intel(alert: Dict) -> Dict:
    """Add threat intelligence to alert"""
    
    threat_analysis = ThreatIntelligenceBase.analyze_alert(
        alert.get("attack_type", "Unknown"),
        alert.get("score", 0),
        alert.get("domain", "Unknown")
    )
    
    alert["threat_intelligence"] = threat_analysis
    
    return alert