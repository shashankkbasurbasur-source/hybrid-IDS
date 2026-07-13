"""
ML Detection Pipeline API — Module 10 (updated).
"""

from fastapi import APIRouter, HTTPException

from backend.storage.db_store import (
    fetch_predictions, fetch_prediction_by_id,
    fetch_prediction_summary, fetch_attack_type_breakdown,
    fetch_dead_letters,
)
from backend.detection.ml.model_manager import model_manager
from backend.detection.features.feature_scaler import feature_scaler
from backend.detection.features.features_metadata import feature_metadata
from backend.detection.performance.performance_monitor import performance_monitor
from backend.detection.queues.feature_extraction_queue import feature_extraction_queue
from backend.detection.queues.detection_queue import detection_queue
from backend.config import FEATURE_VERSION, MODEL_VERSION

router = APIRouter()


@router.get("/predictions")
def get_predictions(limit: int = 100):
    return {"predictions": fetch_predictions(limit)}


@router.get("/predictions/latest")
def get_latest_prediction():
    predictions = fetch_predictions(limit=1)
    if not predictions:
        raise HTTPException(status_code=404, detail="No predictions yet")
    return predictions[0]


@router.get("/predictions/{prediction_id}")
def get_prediction(prediction_id: str):
    prediction = fetch_prediction_by_id(prediction_id)
    if not prediction:
        raise HTTPException(status_code=404, detail=f"Prediction '{prediction_id}' not found")
    return prediction


@router.get("/model/status")
def model_status():
    return {
        "model_loaded": model_manager.is_loaded(),
        "scaler_loaded": feature_scaler.is_loaded(),
        "feature_metadata_loaded": feature_metadata.is_loaded(),
        "model_version": MODEL_VERSION,
        "feature_version": FEATURE_VERSION,
        "expected_feature_count": model_manager.expected_feature_count(),
    }


@router.get("/model/metadata")
def model_metadata():
    return model_manager.metadata()


@router.get("/model/statistics")
def model_statistics():
    summary = fetch_prediction_summary()
    breakdown = fetch_attack_type_breakdown()
    return {**summary, "attack_types": breakdown}


@router.get("/detection/performance")
def detection_performance():
    return performance_monitor.snapshot(
        detection_queue_size=detection_queue.size(),
        feature_queue_size=feature_extraction_queue.size(),
    )


@router.get("/detection/dead-letters")
def dead_letters(limit: int = 100):
    return {"dead_letters": fetch_dead_letters(limit)}