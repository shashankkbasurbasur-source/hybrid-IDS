from fastapi import APIRouter
from datetime import datetime

router = APIRouter()

@router.get("/status")
def get_fusion_status():
    return {
        "current_score": 85,
        "reasoning": ["NIDS anomalies detected", "HIDS authentication failure"],
        "timeline": [
            {"time": datetime.utcnow().isoformat(), "event": "NIDS Flow anomaly"},
            {"time": datetime.utcnow().isoformat(), "event": "HIDS Auth failure"}
        ],
        "status": "active"
    }
