import numpy as np
from backend.hids.ml.syscall_model_loader import get_registry
from backend.hids.features.syscall_bigram_feature import bigram_vector


def predict_syscall(syscall_names_window: list, base_path: str = "models") -> float:
    registry = get_registry(base_path=base_path)
    vector = bigram_vector(syscall_names_window, registry.vocab)
    feature_array = np.array(vector).reshape(1, -1)
    probability = registry.model.predict_proba(feature_array)[0][1]
    return float(probability)