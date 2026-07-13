"""
HIDS Predictor — replaces backend/detection/ml/host_model.py. Same
job (predict intrusion probability from a host feature vector) but
now validates the vector against feature_schema.py first, instead of
silently accepting any list of the wrong shape.
"""

import numpy as np

from backend.hids.features.feature_schema import validate_vector
from backend.hids.ml.model_loader import get_registry


def predict_host(features: list, base_path: str = "models") -> float:
    validate_vector(features)
    try:
        registry = get_registry(base_path=base_path)
        feature_array = np.array(features).reshape(1, -1)
        probability = registry.hids_model.predict_proba(feature_array)[0][1]
        return float(probability)
    except Exception as e:
        raise RuntimeError(f"HIDS prediction failed: {e}")