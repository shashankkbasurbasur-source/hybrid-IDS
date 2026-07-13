from backend.hids.detection.threat_classifier import (
    ATTACK_BRUTE_FORCE, ATTACK_CREDENTIAL_STUFFING, ATTACK_PASSWORD_SPRAY,
    ATTACK_PRIVILEGE_ESCALATION, ATTACK_RECON, ATTACK_SUSPICIOUS_PROCESS,
    ATTACK_PERSISTENCE, ATTACK_SUSPICIOUS, ATTACK_NORMAL,
)

_MITRE_MAP = {
    ATTACK_BRUTE_FORCE: {"technique": "T1110", "tactic": "Credential Access", "name": "Brute Force"},
    ATTACK_CREDENTIAL_STUFFING: {"technique": "T1110.004", "tactic": "Credential Access", "name": "Credential Stuffing"},
    ATTACK_PASSWORD_SPRAY: {"technique": "T1110.003", "tactic": "Credential Access", "name": "Password Spraying"},
    ATTACK_PRIVILEGE_ESCALATION: {"technique": "T1068", "tactic": "Privilege Escalation", "name": "Exploitation for Privilege Escalation"},
    ATTACK_RECON: {"technique": "T1595", "tactic": "Reconnaissance", "name": "Active Scanning"},
    ATTACK_SUSPICIOUS_PROCESS: {"technique": "T1059", "tactic": "Execution", "name": "Command and Scripting Interpreter"},
    ATTACK_PERSISTENCE: {"technique": "T1053", "tactic": "Persistence", "name": "Scheduled Task/Job"},
    ATTACK_SUSPICIOUS: {"technique": "T1078", "tactic": "Initial Access", "name": "Valid Accounts (Suspicious Use)"},
    ATTACK_NORMAL: {"technique": "None", "tactic": "None", "name": "None"},
}


def map_attack(attack_type: str) -> dict:
    return _MITRE_MAP.get(attack_type, {"technique": "Unknown", "tactic": "Unknown", "name": attack_type})