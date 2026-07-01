"""
Intelligent Hybrid Fusion Engine
"""

from backend.core.constants import (
    FUSION_NETWORK_WEIGHT,
    FUSION_HOST_WEIGHT,
    DECISION_THRESHOLD,
    CRITICAL_THRESHOLD,
    HIGH_THRESHOLD,
    MEDIUM_THRESHOLD,
)


def hybrid_fusion(network_score: float, host_score: float) -> dict:
    """
    Intelligent hybrid fusion with explainability
    
    Args:
        network_score: NIDS probability (0-1)
        host_score: HIDS probability (0-1)
    
    Returns:
        Fusion result with decision and reasoning
    """
    
    # Validation
    if not (0 <= network_score <= 1):
        raise ValueError("Network score must be 0-1")
    if not (0 <= host_score <= 1):
        raise ValueError("Host score must be 0-1")
    
    # Weighted fusion
    final_score = (
        FUSION_NETWORK_WEIGHT * network_score +
        FUSION_HOST_WEIGHT * host_score
    )
    final_score = round(final_score, 4)
    
    # Strong signal detection
    strong_nids = network_score >= 0.75
    strong_hids = host_score >= 0.65
    
    # Decision logic
    if strong_nids or strong_hids:
        decision = "Intrusion"
    elif final_score >= DECISION_THRESHOLD:
        decision = "Intrusion"
    else:
        decision = "Normal"
    
    # Triggered components
    triggered_by = []
    if network_score >= 0.5:
        triggered_by.append("NIDS")
    if host_score >= 0.5:
        triggered_by.append("HIDS")
    
    # Attack domain
    if decision == "Intrusion":
        if host_score > network_score:
            attack_domain = "Host"
            location = "Host System"
        elif network_score > host_score:
            attack_domain = "Network"
            location = "Network Traffic"
        else:
            attack_domain = "Hybrid"
            location = "Hybrid Environment"
    else:
        attack_domain = "None"
        location = "None"
    
    # Reasoning
    reason = []
    
    if decision == "Intrusion":
        if host_score >= 0.70:
            reason.append("Host-based anomaly detected")
        
        if network_score >= 0.70:
            reason.append("Network-based anomaly detected")
        
        if strong_nids and strong_hids:
            reason.append("Confirmed intrusion: Both NIDS and HIDS agree")
        
        if not reason:
            reason.append("Suspicious activity detected by fusion engine")
    else:
        reason.append("No anomaly detected")
    
    # Severity mapping
    max_score = max(network_score, host_score, final_score)
    
    if max_score >= CRITICAL_THRESHOLD:
        severity = "CRITICAL"
    elif max_score >= HIGH_THRESHOLD:
        severity = "HIGH"
    elif max_score >= MEDIUM_THRESHOLD:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    
    return {
        "network_score": round(network_score, 4),
        "host_score": round(host_score, 4),
        "final_score": final_score,
        "decision": decision,
        "triggered_by": triggered_by,
        "attack_domain": attack_domain,
        "location": location,
        "severity": severity,
        "reason": reason,
    }