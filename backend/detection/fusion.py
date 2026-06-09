"""
backend/detection/fusion.py

FIXED FOR PHASE 2:
 - Receives attack_type FROM NIDS
 - Detects HYBRID attacks (both NIDS + HIDS elevated)
 - Returns complete attack classification
 - CRITICAL: attack_type parameter must be used
"""

from backend.alerts.severity import classify_severity
from backend.core.logger import get_logger

logger = get_logger(__name__)

# ──────────────────────────────────────────────────────────────────────────
# THRESHOLDS
# ──────────────────────────────────────────────────────────────────────────

# Basic thresholds (moderate confidence)
NETWORK_THRESHOLD = 0.40
HOST_THRESHOLD = 0.40

# Strong signal thresholds (high confidence - triggers immediate alert)
STRONG_NETWORK = 0.75
STRONG_HOST = 0.60

# Hybrid detection threshold (both sources must be elevated)
HYBRID_NETWORK_MIN = 0.50
HYBRID_HOST_MIN = 0.50


def hybrid_fusion(network_score: float, host_score: float, 
                  nids_attack_type: str = "Suspicious Activity") -> dict:
    """
    Fuse NIDS and HIDS signals to make final security decision.
    
    CRITICAL: nids_attack_type parameter is REQUIRED and MUST be used.
    This is what communicates the attack classification to the dashboard.
    
    Args:
        network_score: NIDS confidence [0, 1]
        host_score: HIDS confidence [0, 1]
        nids_attack_type: Attack classification from NIDS (e.g., "Port Scan")
    
    Returns:
        dict with:
        - decision: "Normal" or "Intrusion"
        - final_score: Weighted fusion score
        - attack_type: Specific attack classification
        - severity: CRITICAL / HIGH / MEDIUM / LOW
        - triggered_by: ["NIDS"] or ["HIDS"] or ["NIDS", "HIDS"]
        - reason: List of detection reasons
    """
    
    # ──────────────────────────────────────────────────────────────────────
    # WEIGHTED FUSION SCORE
    # ──────────────────────────────────────────────────────────────────────
    # 60% weight to NIDS, 40% to HIDS
    final_score = (0.6 * network_score) + (0.4 * host_score)
    
    logger.debug("Fusion: NIDS=%.4f, HIDS=%.4f, weighted=%.4f",
                 network_score, host_score, final_score)
    
    # ──────────────────────────────────────────────────────────────────────
    # SIGNAL DETECTION
    # ──────────────────────────────────────────────────────────────────────
    nids_basic = network_score >= NETWORK_THRESHOLD
    hids_basic = host_score >= HOST_THRESHOLD
    nids_strong = network_score >= STRONG_NETWORK
    hids_strong = host_score >= STRONG_HOST
    
    # Hybrid detection: both sources elevated
    is_hybrid = (network_score >= HYBRID_NETWORK_MIN and 
                 host_score >= HYBRID_HOST_MIN)
    
    # ──────────────────────────────────────────────────────────────────────
    # DECISION LOGIC
    # ──────────────────────────────────────────────────────────────────────
    
    # CRITICAL: Any strong signal = Intrusion
    if nids_strong or hids_strong:
        decision = "Intrusion"
        logger.warning("STRONG signal detected: NIDS=%.3f, HIDS=%.3f", 
                      network_score, host_score)
    
    # Both moderate signals = Intrusion
    elif nids_basic and hids_basic:
        decision = "Intrusion"
        logger.warning("Both NIDS and HIDS signals detected")
    
    # Either signal = Intrusion
    elif nids_basic or hids_basic:
        decision = "Intrusion"
        if nids_basic:
            logger.warning("NIDS signal: %.3f", network_score)
        if hids_basic:
            logger.warning("HIDS signal: %.3f", host_score)
    
    # No signals = Normal
    else:
        decision = "Normal"
        logger.info("No intrusion detected (NIDS=%.3f, HIDS=%.3f)",
                   network_score, host_score)
    
    # ──────────────────────────────────────────────────────────────────────
    # ATTACK TYPE CLASSIFICATION
    # CRITICAL: nids_attack_type must be properly classified here
    # ──────────────────────────────────────────────────────────────────────
    
    if decision == "Normal":
        attack_type = "Normal Traffic"
        attack_domain = "None"
        triggered_by = []
        
    # HYBRID ATTACK: Both NIDS and HIDS strong (most serious)
    elif nids_strong and hids_strong:
        attack_type = "Multi-Stage Hybrid Attack"
        attack_domain = "Network + Host"
        triggered_by = ["NIDS", "HIDS"]
        logger.critical("HYBRID ATTACK: Network + Host combined! Score=%.3f",
                       final_score)
    
    # HYBRID ATTACK: Both moderate (possible early stages)
    elif is_hybrid and nids_basic and hids_basic:
        attack_type = "Multi-Stage Hybrid Attack"
        attack_domain = "Network + Host"
        triggered_by = ["NIDS", "HIDS"]
        logger.warning("HYBRID ATTACK POTENTIAL: Both sources elevated")
    
    # PURE NETWORK ATTACK (NIDS only)
    elif nids_strong:
        # Use the classification from NIDS model
        attack_type = nids_attack_type or "Network Attack (DoS / Flood)"
        attack_domain = "Network"
        triggered_by = ["NIDS"]
        logger.warning("Network attack: %s (score=%.3f)", attack_type, network_score)
    
    # PURE HOST ATTACK (HIDS only)
    elif hids_strong:
        attack_type = "Brute Force / Unauthorized Access"
        attack_domain = "Host"
        triggered_by = ["HIDS"]
        logger.warning("Host attack: %s (score=%.3f)", attack_type, host_score)
    
    # MODERATE NETWORK SIGNAL
    elif nids_basic:
        attack_type = nids_attack_type or "Reconnaissance / Port Scan"
        attack_domain = "Network"
        triggered_by = ["NIDS"]
        logger.info("Network signal: %s (score=%.3f)", attack_type, network_score)
    
    # MODERATE HOST SIGNAL
    elif hids_basic:
        attack_type = "Suspicious Activity"
        attack_domain = "Host"
        triggered_by = ["HIDS"]
        logger.info("Host signal (score=%.3f)", host_score)
    
    # FALLBACK
    else:
        attack_type = "Suspicious Activity"
        attack_domain = "Unknown"
        triggered_by = []
    
    # ──────────────────────────────────────────────────────────────────────
    # SEVERITY CLASSIFICATION
    # ──────────────────────────────────────────────────────────────────────
    severity = classify_severity(final_score, decision)
    
    # ──────────────────────────────────────────────────────────────────────
    # REASONING
    # ──────────────────────────────────────────────────────────────────────
    reasons = []
    
    if nids_basic:
        reasons.append(f"Network signal: {network_score:.3f} ({nids_attack_type})")
    if hids_basic:
        reasons.append(f"Host signal: {host_score:.3f}")
    if not reasons:
        reasons.append("Below detection thresholds")
    
    # ──────────────────────────────────────────────────────────────────────
    # RETURN COMPLETE RESULT
    # ──────────────────────────────────────────────────────────────────────
    
    return {
        "decision": decision,
        "final_score": round(final_score, 4),
        "attack_type": attack_type,  # CRITICAL: This value reaches dashboard
        "attack_domain": attack_domain,
        "severity": severity,
        "location": "Network" if attack_domain == "Network" else "Host" if attack_domain == "Host" else "Unknown",
        "triggered_by": triggered_by,
        "reason": reasons,
    }