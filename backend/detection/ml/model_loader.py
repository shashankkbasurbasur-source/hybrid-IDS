import pickle
from pathlib import Path


class ModelRegistry:

    def __init__(self):

        base_path = Path("models")

        try:
            # NIDS model
            with open(base_path / "random_forest_model.pkl", "rb") as f:
                self.nids_model = pickle.load(f)

            # HIDS model
            with open(base_path / "hids_model.pkl", "rb") as f:
                hids_loaded = pickle.load(f)

            if isinstance(hids_loaded, tuple):
                self.hids_model = hids_loaded[0]
            else:
                self.hids_model = hids_loaded

            # scaler
            with open(base_path / "scaler.pkl", "rb") as f:
                self.scaler = pickle.load(f)

            print("[✓] ML Models Loaded Successfully")

        except Exception as e:
            raise RuntimeError(f"Failed to load ML models: {e}")


models = ModelRegistry()