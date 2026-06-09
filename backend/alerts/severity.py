"""backend/alerts/severity.py"""

def classify_severity(score: float, decision: str = "Intrusion") -> str:
    if decision == "Normal":
        return "LOW"
    if score >= 0.85: return "CRITICAL"
    if score >= 0.70: return "HIGH"
    if score >= 0.50: return "MEDIUM"
    return "LOW"

def severity_to_int(s: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(s.upper(), 0)