from backend.hids.features.feature_schema import vector_to_dict

ATTACK_NORMAL = "Normal"
ATTACK_BRUTE_FORCE = "Brute Force"
ATTACK_CREDENTIAL_STUFFING = "Credential Stuffing"
ATTACK_PASSWORD_SPRAY = "Password Spray"
ATTACK_PRIVILEGE_ESCALATION = "Privilege Escalation"
ATTACK_RECON = "Reconnaissance"
ATTACK_SUSPICIOUS_PROCESS = "Suspicious Process"
ATTACK_PERSISTENCE = "Persistence"
ATTACK_SUSPICIOUS = "Suspicious Login"


def classify(feature_vector, probability, decision_threshold=0.5, syscall_events=None):
    if probability < decision_threshold:
        return ATTACK_NORMAL

    if syscall_events:
        names = [e.get("syscall_name") for e in syscall_events]
        exes = [e.get("exe") for e in syscall_events if e.get("exe")]

        if "ptrace" in names and any(n in names for n in ("setuid", "setresuid", "setgid")):
            return ATTACK_PRIVILEGE_ESCALATION
        if any(exe and any(p in exe for p in ("/cron", "systemctl", "systemd", "/etc/init.d")) for exe in exes):
            return ATTACK_PERSISTENCE
        if names.count("execve") >= 3 and len(set(exes)) >= 3:
            return ATTACK_SUSPICIOUS_PROCESS

    f = vector_to_dict(feature_vector)
    if f["root_login_attempts"] >= 2 and f["success_after_failure"]:
        return ATTACK_PRIVILEGE_ESCALATION
    if f["unique_src_ips"] >= 5 and f["failed_login_count"] / max(f["unique_src_ips"], 1) <= 2:
        return ATTACK_PASSWORD_SPRAY
    if f["unique_usernames"] >= 6 and f["unique_src_ips"] <= 2:
        return ATTACK_CREDENTIAL_STUFFING
    if f["invalid_user_attempts"] >= 3 and f["failed_login_count"] <= 10:
        return ATTACK_RECON
    if f["max_repeated_failures"] >= 5:
        return ATTACK_BRUTE_FORCE
    return ATTACK_SUSPICIOUS


def severity_for(probability):
    if probability >= 0.85:
        return "CRITICAL"
    elif probability >= 0.70:
        return "HIGH"
    elif probability >= 0.40:
        return "MEDIUM"
    return "LOW"