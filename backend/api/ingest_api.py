"""backend/api/ingest_api.py"""
import os, pickle
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional

from backend.ingestions.log_ingest   import LogIngestor
from backend.features.log_features   import LogFeatureExtractor
from backend.detection.service       import run_hybrid_detection
from backend.core.logger             import get_logger
from backend.core.exceptions         import IngestionError

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


class LogRequest(BaseModel):
    log_lines: List[str] = Field(...)

class RunRequest(BaseModel):
    log_file:     str           = Field("sample_logs.txt")
    packet_count: int           = Field(10, ge=1, le=200)
    interface:    Optional[str] = Field(None)


@router.post("/log", summary="Analyse raw log lines")
@router.post("/logs", summary="Analyse raw log lines")
def analyse_log(req: LogRequest):
    from backend.parsing.ssh_parser import SSHLogParser
    parser = SSHLogParser()
    events = [parser.parse_line(l) for l in req.log_lines]
    events = [e for e in events if e is not None]
    host_features    = LogFeatureExtractor().extract(events)
    network_features = [0.0] * _nids_size()
    return run_hybrid_detection(network_features, host_features)


@router.post("/run", summary="Run full pipeline from log file")
def run_pipeline(req: RunRequest):
    try:
        log_events    = LogIngestor().ingest_file(req.log_file)
        host_features = LogFeatureExtractor().extract(log_events)
        network_features = [0.0] * _nids_size()
        logger.info("ingest/run: %d log events", len(log_events))
        return run_hybrid_detection(network_features, host_features)
    except IngestionError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("Ingest error")
        raise HTTPException(status_code=500, detail=str(e))