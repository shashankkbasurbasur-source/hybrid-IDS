"""
Alert Builder Module
Creates structured security alerts.
"""

from datetime import datetime
from backend.core.constants import (
    HIGH_SEVERITY_THRESHOLD,
    MEDIUM_SEVERITY_THRESHOLD,
)


def build_alert(decision: str, score: float) -> dict:
    """
    Builds structured alert object.

    Args:
        decision (str): "Intrusion" or "Normal"
        score (float): Final fusion confidence score

    Returns:
        dict: Structured alert data
    """

    if decision not in ["Intrusion", "Normal"]:
        raise ValueError("Invalid decision type")

    if decision == "Normal":
        severity = "LOW"
    else:
        if score >= HIGH_SEVERITY_THRESHOLD:
            severity = "HIGH"
        elif score >= MEDIUM_SEVERITY_THRESHOLD:
            severity = "MEDIUM"
        else:
            severity = "LOW"

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "type": decision,
        "severity": severity,
        "confidence": round(score, 4),
        "source": "Hybrid IDS",
    }