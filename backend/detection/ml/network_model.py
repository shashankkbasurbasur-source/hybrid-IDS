"""
backend/detection/ml/network_model.py

FINAL: Returns attack classification + score
Uses attack classifier for multi-class categorization
"""

import os
import pickle
import numpy as np
from typing import Tuple
from backend.detection.ml.model_loader import models
from backend.detection.ml.attack_classifier import AttackClassifier
from backend.core.logger import get_logger
from backend.core.exceptions import PredictionError

logger = get_logger(__name__)

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
_COLS_PKL = os.path.join(_BASE, "models", "network_feature_columns.pkl")


def _expected_features() -> int:
    """Get expected feature count from training."""
    try:
        with open(_COLS_PKL, "rb") as f:
            return len(pickle.load(f))
    except Exception:
        return 77  # Default to CICIDS


def predict_network(features: list) -> Tuple[float, str, float]:
    """
    Predict network threat with classification.
    
    Args:
        features: 77-dim feature vector
    
    Returns:
        (score: float, attack_type: str, confidence: float)
    """
    try:
        n_expected = _expected_features()
        vec = list(features)
        
        # Align to expected size
        if len(vec) > n_expected:
            vec = vec[:n_expected]
        elif len(vec) < n_expected:
            vec = vec + [0.0] * (n_expected - len(vec))
        
        arr = np.array(vec, dtype=np.float32).reshape(1, -1)
        
        # Apply scaler
        if models.scaler is not None:
            arr = models.scaler.transform(arr)
        
        # Get NIDS score
        proba = models.nids_model.predict_proba(arr)[0]
        score = float(proba[1]) if len(proba) > 1 else 0.0
        
        # Classify attack type
        classifier = AttackClassifier()
        class_id, attack_type, confidence = classifier.classify(score, features)
        
        logger.info("NIDS: score=%.4f, attack='%s', confidence=%.3f",
                   score, attack_type, confidence)
        
        return score, attack_type, confidence
    
    except Exception as e:
        logger.error("NIDS prediction failed: %s", e)
        raise PredictionError(f"NIDS prediction failed: {e}") from e