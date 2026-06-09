# backend/detection/ml/model_loader.py

import pickle
from pathlib import Path
from backend.core.logger import get_logger

logger = get_logger(__name__)

BASE_MODEL_DIR = Path(__file__).resolve().parent.parent.parent.parent / "models"


class ModelRegistry:

    def __init__(self):
        try:
            # ── NIDS binary detector ──────────────────────────────────────
            with open(BASE_MODEL_DIR / "random_forest_model.pkl", "rb") as f:
                self.nids_model = pickle.load(f)
            logger.info("NIDS binary model loaded")

            # ── Multi-class attack classifier ─────────────────────────────
            with open(BASE_MODEL_DIR / "attack_classifier.pkl", "rb") as f:
                self.attack_classifier = pickle.load(f)
            with open(BASE_MODEL_DIR / "attack_label_encoder.pkl", "rb") as f:
                self.attack_label_encoder = pickle.load(f)
            with open(BASE_MODEL_DIR / "attack_scaler.pkl", "rb") as f:
                self.attack_scaler = pickle.load(f)
            logger.info("Multi-class attack classifier loaded")

            # ── HIDS SSH model (preferred) ────────────────────────────────
            ssh_path = BASE_MODEL_DIR / "hids_ssh_model.pkl"
            adfa_path = BASE_MODEL_DIR / "hids_model.pkl"

            if ssh_path.exists():
                with open(ssh_path, "rb") as f:
                    loaded = pickle.load(f)
                # saved as (rf, scaler) by train_hids_ssh.py
                if isinstance(loaded, tuple):
                    self.hids_model  = loaded[0]
                    self.hids_scaler = loaded[1]
                else:
                    self.hids_model  = loaded
                    self.hids_scaler = None
                self.hids_vocab = None          # SSH model uses behavioral features, no vocab
                self.hids_mode  = "ssh"
                logger.info("HIDS SSH model loaded")

            elif adfa_path.exists():
                with open(adfa_path, "rb") as f:
                    loaded = pickle.load(f)
                if isinstance(loaded, tuple):
                    self.hids_model  = loaded[0]
                    self.hids_vocab  = loaded[1]   # bigram vocab preserved
                    self.hids_scaler = None
                else:
                    self.hids_model  = loaded
                    self.hids_vocab  = None
                    self.hids_scaler = None
                self.hids_mode = "adfa"
                logger.info("HIDS ADFA model loaded (fallback)")

            else:
                raise FileNotFoundError("No HIDS model found (tried hids_ssh_model.pkl and hids_model.pkl)")

            # ── NIDS scaler ───────────────────────────────────────────────
            with open(BASE_MODEL_DIR / "scaler.pkl", "rb") as f:
                self.scaler = pickle.load(f)
            logger.info("NIDS scaler loaded")

            logger.info("[✓] All models loaded — HIDS mode: %s", self.hids_mode)

        except FileNotFoundError as e:
            raise RuntimeError(f"Model file not found: {e}")
        except Exception as e:
            raise RuntimeError(f"Model load failed: {e}")


models = ModelRegistry()