"""
Hybrid Fusion Engine
Combines NIDS and HIDS outputs into final decision.
Includes explainability, attack classification, and severity.
"""

from backend.core.constants import (
    FUSION_NETWORK_WEIGHT,
    FUSION_HOST_WEIGHT,
    DECISION_THRESHOLD,
)


def hybrid_fusion(network_score: float, host_score: float) -> dict:
    """
    Performs intelligent hybrid fusion with explainable output.

    Args:
        network_score (float): NIDS intrusion probability (0–1)
        host_score (float): HIDS intrusion probability (0–1)

    Returns:
        dict: Final fusion result
    """

    # ------------------------------------------------
    # 1. Input Validation
    # ------------------------------------------------
    if not (0 <= network_score <= 1):
        raise ValueError("Network score must be between 0 and 1")

    if not (0 <= host_score <= 1):
        raise ValueError("Host score must be between 0 and 1")

    # ------------------------------------------------
    # 2. Weighted Hybrid Fusion
    # ------------------------------------------------
    final_score = (
        FUSION_NETWORK_WEIGHT * network_score
        + FUSION_HOST_WEIGHT * host_score
    )

    final_score = round(final_score, 4)

    # ------------------------------------------------
    # 3. Strong Signal Detection
    # ------------------------------------------------
    strong_nids = network_score >= 0.75
    strong_hids = host_score >= 0.60

    # ------------------------------------------------
    # 4. Final Decision Logic
    # ------------------------------------------------
    if strong_nids or strong_hids:
        decision = "Intrusion"

    elif final_score >= DECISION_THRESHOLD:
        decision = "Intrusion"

    else:
        decision = "Normal"

    # ------------------------------------------------
    # 5. Trigger Source
    # ------------------------------------------------
    triggered_by = []

    if network_score >= 0.5:
        triggered_by.append("NIDS")

    if host_score >= 0.5:
        triggered_by.append("HIDS")

    # ------------------------------------------------
    # 6. Attack Domain
    # ------------------------------------------------
    if decision == "Intrusion":

        if host_score > network_score:
            attack_domain = "Host"

        elif network_score > host_score:
            attack_domain = "Network"

        else:
            attack_domain = "Hybrid"

    else:
        attack_domain = "None"

    # ------------------------------------------------
    # 7. Attack Type
    # ------------------------------------------------
    if decision == "Intrusion":

        # Host-based attacks
        if host_score >= 0.80:
            attack_type = "Brute Force / Unauthorized Access"

        # Network attacks
        elif network_score >= 0.80:
            attack_type = "Network Attack (DoS / Scan)"

        # Both high
        elif host_score >= 0.50 and network_score >= 0.50:
            attack_type = "Multi-Stage Hybrid Attack"

        # Generic anomaly
        else:
            attack_type = "Suspicious Activity"

    else:
        attack_type = "None"

    # ------------------------------------------------
    # 8. Location
    # ------------------------------------------------
    if decision == "Intrusion":

        if host_score > network_score:
            location = "Host System"

        elif network_score > host_score:
            location = "Network Traffic"

        else:
            location = "Hybrid Environment"

    else:
        location = "None"

    # ------------------------------------------------
    # 9. Reason / Explainability
    # ------------------------------------------------
    reason = []

    if decision == "Intrusion":

        if host_score >= 0.70:
            reason.append(
                "Multiple failed login attempts detected"
            )

        if network_score >= 0.70:
            reason.append(
                "Abnormal network traffic spike detected"
            )

        if not reason:
            reason.append(
                "Suspicious anomaly detected"
            )

    else:
        reason.append("No anomaly detected")

    # ------------------------------------------------
    # 10. Severity Mapping
    # ------------------------------------------------
    max_score = max(network_score, host_score, final_score)

    if max_score >= 0.85:
        severity = "CRITICAL"

    elif max_score >= 0.70:
        severity = "HIGH"

    elif max_score >= 0.40:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    # ------------------------------------------------
    # 11. Final Response
    # ------------------------------------------------
    return {
        "network_score": round(network_score, 4),
        "host_score": round(host_score, 4),

        "final_score": final_score,
        "decision": decision,

        "triggered_by": triggered_by,

        "attack_domain": attack_domain,
        "attack_type": attack_type,
        "location": location,

        "severity": severity,
        "reason": reason,
    }