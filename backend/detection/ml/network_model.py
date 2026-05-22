"""
Network Intrusion Detection Model Wrapper (NIDS)
"""

import numpy as np
from backend.detection.ml.model_loader import models


def predict_network(features: list) -> float:
    """
    Predicts probability of intrusion using NIDS model.

    Args:
        features (list): Extracted network feature vector

    Returns:
        float: Intrusion probability (0–1)
    """

    if not isinstance(features, list):
        raise ValueError("Network features must be a list")

    if len(features) == 0:
        raise ValueError("Network features list cannot be empty")

    try:
        feature_array = np.array(features).reshape(1, -1)

        probability = models.nids_model.predict_proba(feature_array)[0][1]

        return float(probability)

    except Exception as e:
        raise RuntimeError(f"NIDS prediction failed: {e}")