"""backend/api/detect_api.py"""
import os, pickle
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator
from typing import List
from datetime import datetime, timezone

from backend.detection.service import run_hybrid_detection
from backend.core.logger import get_logger
from backend.core.exceptions import PredictionError

logger = get_logger(__name__)
router = APIRouter()

_BASE     = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_COLS_PKL = os.path.join(_BASE, "models", "network_feature_columns.pkl")

def _nids_size() -> int:
    try:
        with open(_COLS_PKL, "rb") as f:
            return len(pickle.load(f))
    except Exception:
        from backend.detection.ml.model_loader import models
        return int(models.nids_model.n_features_in_)

_N = _nids_size()
logger.info("detect_api: NIDS=%d HIDS=100", _N)


class DetectionRequest(BaseModel):
    network_features: List[float]
    host_features:    List[float]

    @field_validator("network_features")
    @classmethod
    def align_network(cls, v):
        v = list(v)
        if len(v) > _N:   return v[:_N]
        if len(v) < _N:   return v + [0.0] * (_N - len(v))
        return v

    @field_validator("host_features")
    @classmethod
    def align_host(cls, v):
        v = list(v)
        if len(v) > 100:  return v[:100]
        if len(v) < 100:  return v + [0.0] * (100 - len(v))
        return v


@router.post("/", summary="Run Hybrid Intrusion Detection")
def detect(request: DetectionRequest):
    try:
        result = run_hybrid_detection(
            list(request.network_features),
            list(request.host_features),
        )
        return {**result, "timestamp": datetime.now(timezone.utc).isoformat()}
    except PredictionError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.exception("Detection pipeline error")
        raise HTTPException(status_code=500, detail=str(e))