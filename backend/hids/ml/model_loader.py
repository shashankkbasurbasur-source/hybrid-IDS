"""
HIDS Model Loader
==================
Loads the retrained auth-log HIDS model. No tuple to unpack — the old
ADFA-LD model.pkl was (RandomForest, bigram_vocabulary); the new
hids_model.pkl is a plain RandomForest trained on the auth-log
schema, so loading it is a single pickle.load.
"""

import pickle
from pathlib import Path


class HIDSModelRegistry:
    def __init__(self, base_path: str = "models"):
        base_path = Path(base_path)
        try:
            with open(base_path / "hids_model.pkl", "rb") as f:
                self.hids_model = pickle.load(f)
            print("[✓] HIDS model (auth-log schema) loaded successfully")
        except Exception as e:
            raise RuntimeError(f"Failed to load HIDS model: {e}")


_registry = None  # lazily instantiated so import doesn't require the model to exist yet


def get_registry(base_path: str = "models") -> HIDSModelRegistry:
    global _registry
    if _registry is None:
        _registry = HIDSModelRegistry(base_path=base_path)
    return _registry