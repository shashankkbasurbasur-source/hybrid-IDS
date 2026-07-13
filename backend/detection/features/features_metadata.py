"""
Feature Metadata Loader.
Authoritative feature ORDER comes from models/network_feature_columns.pkl
(saved during training) — never hardcoded here. feature_metadata.json is
loaded only for informational fields (training date, dataset, algorithm);
its feature_count is cross-checked against the pkl but the pkl always wins.
"""

import json
import pickle
from pathlib import Path

from backend.core.logger import get_logger

logger = get_logger(__name__)

COLUMNS_PATH = Path("models/network_feature_columns.pkl")
METADATA_JSON_PATH = Path("models/feature_metadata.json")


class FeatureMetadataError(Exception):
    pass


class FeatureMetadata:
    def __init__(self):
        self._metadata = None
        self._load()

    def _load(self):
        if not COLUMNS_PATH.exists():
            logger.error(
                f"'{COLUMNS_PATH}' not found. This file is the authoritative "
                "feature order and must exist before the pipeline can run."
            )
            self._metadata = None
            return

        try:
            with open(COLUMNS_PATH, "rb") as f:
                columns = pickle.load(f)
            columns = list(columns)
        except Exception as e:
            logger.error(f"Failed to load {COLUMNS_PATH}: {e}")
            self._metadata = None
            return

        json_meta = {}
        if METADATA_JSON_PATH.exists():
            try:
                with open(METADATA_JSON_PATH, "r") as f:
                    json_meta = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(f"Failed to load {METADATA_JSON_PATH} (non-fatal): {e}")

        declared_count = json_meta.get("feature_count")
        if declared_count and declared_count != len(columns):
            logger.warning(
                f"feature_metadata.json declares {declared_count} features but "
                f"network_feature_columns.pkl has {len(columns)}. "
                "The .pkl file is authoritative — using its count/order."
            )

        self._metadata = {
            **{k: v for k, v in json_meta.items() if k not in ("feature_columns", "feature_count")},
            "feature_columns": columns,
            "feature_count": len(columns),
        }
        logger.info(f"Feature metadata loaded: {len(columns)} features from {COLUMNS_PATH}")

    def reload(self):
        self._load()

    def is_loaded(self) -> bool:
        return self._metadata is not None

    @property
    def feature_columns(self) -> list:
        if self._metadata is None:
            raise FeatureMetadataError("Feature metadata not loaded")
        return self._metadata["feature_columns"]

    @property
    def feature_count(self) -> int:
        if self._metadata is None:
            raise FeatureMetadataError("Feature metadata not loaded")
        return self._metadata["feature_count"]

    def as_dict(self) -> dict:
        return dict(self._metadata) if self._metadata else {}


feature_metadata = FeatureMetadata()