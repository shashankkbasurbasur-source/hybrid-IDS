"""
backend/detection/ml/network_model.py

FIXED FOR PHASE 2:
 - Returns BOTH score AND attack_type
 - Properly aligns feature vectors to exact trained size
 - Applies scaler before prediction
 - Critical: attack_type MUST reach fusion engine
"""

import os
import pickle
import numpy as np
from typing import Tuple
from backend.detection.ml.model_loader import models
from backend.core.logger import get_logger
from backend.core.exceptions import PredictionError

logger = get_logger(__name__)

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
_COLS_PKL = os.path.join(_BASE, "models", "network_feature_columns.pkl")


def _expected_features() -> int:
    """Get EXACT feature count from training artifacts."""
    try:
        with open(_COLS_PKL, "rb") as f:
            cols = pickle.load(f)
            return len(cols)
    except Exception as e:
        logger.warning("Could not load feature columns: %s. Using model.n_features_in_", e)
        return int(models.nids_model.n_features_in_)


def _classify_attack_type(network_score: float, feature_vector: np.ndarray) -> str:
    """
    Classify the specific attack type based on NIDS score and features.
    Uses heuristics since we may not have a multi-class classifier.
    """
    # Score-based classification (heuristic)
    if network_score < 0.3:
        return "Normal Traffic"
    elif network_score < 0.5:
        return "Suspicious Activity"
    elif network_score < 0.65:
        return "Reconnaissance / Port Scan"
    elif network_score < 0.80:
        return "Network Attack (DoS / Flood)"
    else:
        return "Network Attack (DoS / Flood)"


def predict_network(features: list) -> Tuple[float, str]:
    """
    Predict network threat.
    
    Args:
        features: List of floats (network feature vector)
    
    Returns:
        (score: float [0,1], attack_type: str)
        
    CRITICAL: attack_type MUST be passed to fusion engine!
    """
    try:
        n_expected = _expected_features()
        vec = list(features)
        
        logger.debug("NIDS: received %d features, expecting %d", len(vec), n_expected)
        
        # ── Align feature vector to exact expected size ──────────────────
        if len(vec) > n_expected:
            logger.debug("NIDS: truncating %d → %d features", len(vec), n_expected)
            vec = vec[:n_expected]
        elif len(vec) < n_expected:
            logger.debug("NIDS: padding %d → %d features", len(vec), n_expected)
            vec = vec + [0.0] * (n_expected - len(vec))
        
        # ── Convert to numpy array ─────────────────────────────────────
        arr = np.array(vec, dtype=np.float32).reshape(1, -1)
        
        # ── Apply scaler (CRITICAL - was missing before) ────────────────
        if models.scaler is not None:
            try:
                arr = models.scaler.transform(arr)
                logger.debug("NIDS: scaler applied")
            except Exception as e:
                logger.warning("NIDS: scaler failed, using raw features: %s", e)
        
        # ── Get prediction probability ─────────────────────────────────
        proba = models.nids_model.predict_proba(arr)[0]
        
        # For binary classifier: proba = [p_benign, p_attack]
        if len(proba) == 2:
            score = float(proba[1])  # Probability of attack (class 1)
        else:
            # Fallback for unexpected output
            score = float(proba[0]) if len(proba) > 0 else 0.0
        
        logger.debug("NIDS: raw score = %.4f", score)
        
        # ── Classify attack type (CRITICAL - this must reach fusion!) ───
        attack_type = _classify_attack_type(score, arr)
        
        logger.info("NIDS: score=%.4f, attack_type='%s'", score, attack_type)
        
        # ── CRITICAL: Return BOTH values to calling function ───────────
        return score, attack_type
    
    except Exception as e:
        logger.error("NIDS prediction failed: %s", e)
        raise PredictionError(f"NIDS prediction failed: {e}") from e