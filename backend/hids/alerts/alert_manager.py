import uuid
import time
from datetime import datetime
from backend.hids.alerts.incident_logger import log_incident

_last_dispatch_by_ip = {}
ALERT_COOLDOWN_SECONDS = 60

_RECOMMENDATIONS = {
    "Brute Force": "Lock or rate-limit the source IP; enforce account lockout after repeated failures.",
    "Credential Stuffing": "Enable MFA; review credential reuse across accounts targeted from this IP.",
    "Password Spray": "Block/monitor the source IP range; check for a coordinated campaign across hosts.",
    "Privilege Escalation": "Immediately review root/sudo access; rotate credentials; investigate the session.",
    "Reconnaissance": "Monitor the source IP; consider blocking after repeated invalid-user probing.",
    "Suspicious Process": "Investigate the flagged process tree (pid/ppid/exe) for signs of malicious execution.",
    "Persistence": "Check cron, systemd units, and startup scripts for unauthorized entries.",
    "Suspicious Login": "Review the session manually; confirm with the account owner.",
}


def build_and_dispatch_alert(source_ip, probability, attack_type, severity, mitre,
                              feature_vector, auth_score=None, syscall_score=None):
    now = time.monotonic()
    last = _last_dispatch_by_ip.get(source_ip)
    if last is not None and (now - last) < ALERT_COOLDOWN_SECONDS:
        return None  # suppress duplicate alert for same source within cooldown
    _last_dispatch_by_ip[source_ip] = now

    alert = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat(),
        "source": "Hybrid IDS",
        "source_ip": source_ip,
        "attack_type": attack_type,
        "severity": severity,
        "confidence": round(float(probability), 4),
        "auth_score": round(float(auth_score), 4) if auth_score is not None else None,
        "syscall_score": round(float(syscall_score), 4) if syscall_score is not None else None,
        "mitre_technique": mitre.get("technique"),
        "mitre_tactic": mitre.get("tactic"),
        "recommendation": _RECOMMENDATIONS.get(attack_type, "Review the flagged incident manually."),
    }
    log_incident(alert, feature_vector=feature_vector)
    return alert