"""
Model Manager — Module 4 (rewritten).
Feature count authority is ALWAYS model.n_features_in_ — never a config
value. Also surfaces training metadata (from feature_metadata.json) for
reproducibility.
"""

import pickle
import time
import threading

from backend.config import MODEL_PATH, MODEL_NAME, MODEL_VERSION
from backend.detection.features.features_metadata import feature_metadata
from backend.core.logger import get_logger

logger = get_logger(__name__)


class ModelLoadError(Exception):
    pass


class ModelManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._model = None
        self._model_version = MODEL_VERSION
        self._loaded_at = None
        self._expected_feature_count = None
        self._load()

    def _load(self):
        with self._lock:
            try:
                with open(MODEL_PATH, "rb") as f:
                    self._model = pickle.load(f)

                # AUTHORITATIVE feature count — from the model itself
                self._expected_feature_count = getattr(self._model, "n_features_in_", None)
                self._loaded_at = time.time()

                # Cross-check against feature_metadata.json (informational, not authoritative)
                if feature_metadata.is_loaded():
                    meta_count = feature_metadata.feature_count
                    if self._expected_feature_count and meta_count != self._expected_feature_count:
                        logger.error(
                            f"MISMATCH: model expects {self._expected_feature_count} features, "
                            f"but feature_metadata.json declares {meta_count}. "
                            "These MUST match — retrain or regenerate metadata."
                        )

                logger.info(
                    f"Model '{MODEL_NAME}' v{self._model_version} loaded from {MODEL_PATH} "
                    f"(model expects {self._expected_feature_count} features)"
                )
            except Exception as e:
                self._model = None
                logger.error(f"Failed to load model from {MODEL_PATH}: {e}")
                raise ModelLoadError(f"Model load failed: {e}")

    def reload(self):
        logger.info("Reloading model...")
        self._load()
        feature_metadata.reload()

    def is_loaded(self) -> bool:
        with self._lock:
            return self._model is not None

    def expected_feature_count(self):
        with self._lock:
            return self._expected_feature_count

    def metadata(self) -> dict:
        """Training reproducibility info: date, dataset, algorithm, etc."""
        meta = feature_metadata.as_dict()
        with self._lock:
            meta["loaded_at"] = self._loaded_at
            meta["model_expected_feature_count"] = self._expected_feature_count
        return meta

    def predict(self, scaled_vector: list) -> dict:
        with self._lock:
            if self._model is None:
                raise ModelLoadError("Model is not loaded")

            if self._expected_feature_count and len(scaled_vector) != self._expected_feature_count:
                raise ModelLoadError(
                    f"Feature count mismatch: model expects {self._expected_feature_count}, "
                    f"got {len(scaled_vector)}"
                )

            start = time.monotonic()
            prediction = self._model.predict([scaled_vector])[0]
            probabilities = self._model.predict_proba([scaled_vector])[0]
            inference_ms = (time.monotonic() - start) * 1000

            confidence = float(max(probabilities))
            attack_probability = float(probabilities[1]) if len(probabilities) > 1 else float(prediction)

            return {
                "prediction": int(prediction),
                "confidence": confidence,
                "probability": attack_probability,
                "inference_time_ms": round(inference_ms, 4),
                "model_name": MODEL_NAME,
                "model_version": self._model_version,
            }


model_manager = ModelManager()