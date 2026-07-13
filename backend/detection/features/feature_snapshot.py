"""
Feature Snapshot
Stores the RAW (pre-scaling) feature vector alongside its hash, before
scaling happens. Useful for debugging and for the verification test that
compares live extraction against offline/training-time feature generation.
"""

import hashlib
import json

from backend.storage.db_store import insert_feature_snapshot
from backend.core.logger import get_logger

logger = get_logger(__name__)


def compute_vector_hash(vector: list) -> str:
    serialized = json.dumps([round(v, 6) for v in vector])
    return hashlib.sha256(serialized.encode()).hexdigest()[:16]


def snapshot(flow_key: str, flow_id: str, raw_vector: list) -> str:
    """Returns the computed hash so callers can attach it to the prediction record."""
    vector_hash = compute_vector_hash(raw_vector)

    try:
        insert_feature_snapshot({
            "flow_id": flow_id,
            "flow_key": flow_key,
            "feature_vector": json.dumps(raw_vector),
            "feature_vector_hash": vector_hash,
        })
    except Exception as e:
        logger.error(f"Failed to store feature snapshot for {flow_key}: {e}")

    return vector_hash