"""
Feature Scaler — Module 3.
Wraps the SAVED scaler from training. Never fits a new scaler at runtime.
"""

import pickle

from backend.config import SCALER_PATH
from backend.core.logger import get_logger

logger = get_logger(__name__)


class FeatureScalerError(Exception):
    pass


class FeatureScaler:
    def __init__(self):
        self._scaler = None
        self._load()

    def _load(self):
        try:
            with open(SCALER_PATH, "rb") as f:
                self._scaler = pickle.load(f)
            logger.info(f"Scaler loaded from {SCALER_PATH}")
        except Exception as e:
            logger.error(f"Failed to load scaler from {SCALER_PATH}: {e}")
            self._scaler = None

    def is_loaded(self) -> bool:
        return self._scaler is not None

    def transform(self, vector: list) -> list:
        if self._scaler is None:
            raise FeatureScalerError("Scaler is not loaded")

        try:
            scaled = self._scaler.transform([vector])[0]
            return list(scaled)
        except Exception as e:
            raise FeatureScalerError(f"Scaling failed: {e}")


feature_scaler = FeatureScaler()