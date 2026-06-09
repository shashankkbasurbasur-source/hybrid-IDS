"""backend/alerts/alert_builder.py"""
import uuid
from datetime import datetime, timezone
from backend.alerts.severity import classify_severity

_MITRE = {
    "Brute Force / Unauthorized Access": "T1110 - Brute Force",
    "Network Attack (DoS / Scan)":        "T1498 - Network DoS",
    "Multi-Stage Hybrid Attack":          "T1021 - Remote Services",
    "Reconnaissance / Port Scan":         "T1046 - Network Service Scanning",
    "Suspicious Activity":                "T1071 - Application Layer Protocol",
}

def build_alert(decision: str, score: float, fusion_result: dict = None) -> dict:
    fr          = fusion_result or {}
    attack_type = fr.get("attack_type", "None")
    severity    = classify_severity(score, decision)
    return {
        "alert_id":      str(uuid.uuid4()),
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "type":          decision,
        "severity":      severity,
        "confidence":    round(score, 4),
        "source":        "Hybrid IDS",
        "attack_type":   attack_type,
        "attack_domain": fr.get("attack_domain", "None"),
        "location":      fr.get("location",      "None"),
        "triggered_by":  fr.get("triggered_by",  []),
        "reason":        fr.get("reason",         ["No anomaly detected"]),
        "mitre":         _MITRE.get(attack_type, "N/A") if decision == "Intrusion" else "N/A",
        "network_score": fr.get("network_score",  0.0),
        "host_score":    fr.get("host_score",     0.0),
        "final_score":   fr.get("final_score",    score),
    }