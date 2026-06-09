"""
backend/detection/service.py

FIXED FOR PHASE 2:
 - Receives attack_type FROM predict_network()
 - Passes attack_type TO hybrid_fusion()
 - CRITICAL: Ensures attack classification reaches dashboard
"""

from typing import Tuple
from backend.detection.ml.network_model import predict_network
from backend.detection.ml.host_model import predict_host
from backend.detection.fusion import hybrid_fusion
from backend.alerts.alert_builder import build_alert
from backend.storage.db_store import alert_store
from backend.storage.file_store import file_logger
from backend.core.logger import get_logger

logger = get_logger(__name__)


def run_hybrid_detection(network_features: list, host_features: list) -> dict:
    """
    Full hybrid detection pipeline.
    
    CRITICAL FIXES:
    1. predict_network() now returns BOTH (score, attack_type)
    2. attack_type is passed to hybrid_fusion()
    3. Fusion result includes attack classification
    4. Dashboard receives complete attack information
    """
    
    # ──────────────────────────────────────────────────────────────────────
    # STEP 1: NIDS (Network IDS) - Returns score AND attack type
    # ──────────────────────────────────────────────────────────────────────
    try:
        network_score, nids_attack_type = predict_network(network_features)
    except Exception as e:
        logger.error("NIDS prediction failed: %s. Using zero score.", e)
        network_score = 0.0
        nids_attack_type = "Suspicious Activity"
    
    logger.info("▶ NIDS Result: score=%.4f, attack='%s'", 
                network_score, nids_attack_type)
    
    # ──────────────────────────────────────────────────────────────────────
    # STEP 2: HIDS (Host IDS) - Returns score only
    # ──────────────────────────────────────────────────────────────────────
    try:
        host_score = predict_host(host_features)
    except Exception as e:
        logger.error("HIDS prediction failed: %s. Using zero score.", e)
        host_score = 0.0
    
    logger.info("▶ HIDS Result: score=%.4f", host_score)
    
    # ──────────────────────────────────────────────────────────────────────
    # STEP 3: FUSION ENGINE - Correlates NIDS + HIDS with attack type
    # CRITICAL: nids_attack_type must be passed here!
    # ──────────────────────────────────────────────────────────────────────
    try:
        fusion_result = hybrid_fusion(
            network_score=network_score,
            host_score=host_score,
            nids_attack_type=nids_attack_type  # CRITICAL: Pass attack type
        )
    except Exception as e:
        logger.error("Fusion failed: %s. Using default result.", e)
        fusion_result = {
            "decision": "Normal",
            "final_score": max(network_score, host_score),
            "attack_type": "Suspicious Activity",
            "attack_domain": "Unknown",
            "severity": "LOW",
            "location": "Unknown",
            "triggered_by": [],
            "reason": ["Fusion engine error"],
        }
    
    logger.info("▶ Fusion Result: decision=%s, severity=%s, attack='%s'",
                fusion_result["decision"],
                fusion_result.get("severity", "?"),
                fusion_result.get("attack_type", "?"))
    
    # ──────────────────────────────────────────────────────────────────────
    # STEP 4: BUILD ALERT
    # ──────────────────────────────────────────────────────────────────────
    try:
        alert = build_alert(
            decision=fusion_result["decision"],
            score=fusion_result["final_score"],
            fusion_result={
                **fusion_result,
                "network_score": network_score,
                "host_score": host_score,
            },
        )
    except Exception as e:
        logger.error("Alert building failed: %s", e)
        alert = {
            "alert_id": "error",
            "timestamp": "unknown",
            "type": "Error",
            "severity": "LOW",
            "confidence": 0.0,
        }
    
    # ──────────────────────────────────────────────────────────────────────
    # STEP 5: PERSIST ALERT
    # ──────────────────────────────────────────────────────────────────────
    try:
        alert_store.save(alert)
        file_logger.log(alert)
        logger.debug("Alert persisted: %s", alert.get("alert_id", "?"))
    except Exception as e:
        logger.warning("Alert persistence failed: %s", e)
    
    # ──────────────────────────────────────────────────────────────────────
    # STEP 6: RETURN COMPLETE RESULT
    # ──────────────────────────────────────────────────────────────────────
    result = {
        "network_score": round(network_score, 4),
        "host_score": round(host_score, 4),
        "final_score": fusion_result["final_score"],
        "decision": fusion_result["decision"],
        "attack_type": fusion_result.get("attack_type", "Suspicious Activity"),
        "attack_domain": fusion_result.get("attack_domain", "Unknown"),
        "location": fusion_result.get("location", "Unknown"),
        "severity": fusion_result.get("severity", "LOW"),
        "reason": fusion_result.get("reason", ["No anomaly detected"]),
        "triggered_by": fusion_result.get("triggered_by", []),
        "mitre": alert.get("mitre", "N/A"),
        "alert": alert,
    }
    
    logger.info("═" * 80)
    logger.info("DETECTION COMPLETE: %s | Score=%.4f | Severity=%s",
                result["decision"],
                result["final_score"],
                result["severity"])
    logger.info("═" * 80)
    
    return result