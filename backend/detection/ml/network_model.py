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


# backend/detection/ml/network_model.py — fix predict_network signature drift
def predict_network(features: list) -> float:
    """
    Kept as a single-float return for legacy callers (service.py, packet_api.py).
    Full classification (attack_type, confidence) is now obtained via
    NIDSDetectionEngine.predict_flow(), which is the canonical entry point
    used by the Fusion Engine (see section 3). This function stays thin
    on purpose — one probability, nothing else.
    """
    n_expected = _expected_features()
    vec = list(features)
    if len(vec) > n_expected:
        vec = vec[:n_expected]
    elif len(vec) < n_expected:
        vec = vec + [0.0] * (n_expected - len(vec))

    arr = np.array(vec, dtype=np.float32).reshape(1, -1)
    if models.scaler is not None:
        arr = models.scaler.transform(arr)

    proba = models.nids_model.predict_proba(arr)[0]
    return float(proba[1]) if len(proba) > 1 else 0.0