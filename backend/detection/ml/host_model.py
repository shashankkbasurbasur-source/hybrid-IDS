"""backend/detection/ml/host_model.py"""
import numpy as np
from backend.detection.ml.model_loader import models
from backend.core.logger import get_logger
from backend.core.exceptions import PredictionError

logger = get_logger(__name__)

def predict_host(features: list) -> float:
    try:
        if not features or sum(abs(x) for x in features) == 0:
            return 0.0
            
        n   = int(models.hids_model.n_features_in_)
        vec = list(features)
        if len(vec) > n:   vec = vec[:n]
        elif len(vec) < n: vec = vec + [0.0] * (n - len(vec))
        arr   = np.array(vec, dtype=float).reshape(1, -1)
        proba = models.hids_model.predict_proba(arr)[0]
        return float(proba[1]) if len(proba) > 1 else float(proba[0])
    except Exception as e:
        raise PredictionError(f"HIDS prediction failed: {e}") from e