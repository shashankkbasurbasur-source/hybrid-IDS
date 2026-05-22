"""
Host Intrusion Detection Model Wrapper (HIDS)
"""

import numpy as np
from backend.detection.ml.model_loader import models


def predict_host(features: list) -> float:
    """
    Predicts probability of intrusion using HIDS model.

    Args:
        features (list): Extracted host feature vector

    Returns:
        float: Intrusion probability (0-1)
    """

    if not isinstance(features, list):
        raise ValueError("Host features must be a list")

    if len(features) == 0:
        raise ValueError("Host features list cannot be empty")

    try:
        feature_array = np.array(features).reshape(1, -1)

        probability = models.hids_model.predict_proba(feature_array)[0][1]

        return float(probability)

    except Exception as e:
        raise RuntimeError(f"HIDS prediction failed: {e}")