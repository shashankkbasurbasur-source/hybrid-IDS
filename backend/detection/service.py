"""
Hybrid Detection Service
Orchestrates ML models, fusion engine, and alert builder.
"""

from backend.detection.ml.network_model import predict_network
from backend.detection.ml.host_model import predict_host
from backend.detection.fusion import hybrid_fusion
from backend.alerts.alert_builder import build_alert


def run_hybrid_detection(network_features: list, host_features: list) -> dict:
    """
    Main hybrid detection pipeline.

    Args:
        network_features (list): Extracted network feature vector
        host_features (list): Extracted host feature vector

    Returns:
        dict: Full hybrid IDS result
    """

    # -----------------------------
    # Step 1 — Individual Predictions
    # -----------------------------
    network_score = predict_network(network_features)
    host_score = predict_host(host_features)

    # -----------------------------
    # Step 2 — Hybrid Fusion
    # -----------------------------
    fusion_result = hybrid_fusion(
        network_score,
        host_score
    )

    # -----------------------------
    # Step 3 — Build Alert
    # -----------------------------
    alert = build_alert(
        fusion_result["decision"],
        fusion_result["final_score"],
    )

    # -----------------------------
    # Step 4 — Final Response
    # -----------------------------
    return {
        # Core Scores
        "network_score": round(network_score, 4),
        "host_score": round(host_score, 4),

        # Fusion Output
        "final_score": fusion_result["final_score"],
        "decision": fusion_result["decision"],

        # 🔥 Explainability Fields
        "attack_type": fusion_result.get(
            "attack_type",
            "None"
        ),

        "location": fusion_result.get(
            "location",
            "None"
        ),

        "reason": fusion_result.get(
            "reason",
            ["No anomaly detected"]
        ),

        "severity": fusion_result.get(
            "severity",
            "LOW"
        ),

        # Alert Metadata
        "alert": alert,
    }