"""
Detection API Routes
Exposes Hybrid IDS as REST endpoint with full explainability.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List
from datetime import datetime

from backend.detection.service import run_hybrid_detection

router = APIRouter()


# -----------------------------
# Request Schema
# -----------------------------
class DetectionRequest(BaseModel):
    network_features: List[float] = Field(..., description="Network feature vector (78 values)")
    host_features: List[float] = Field(..., description="Host feature vector (100 values)")


# -----------------------------
# Response Schema
# -----------------------------
class DetectionResponse(BaseModel):
    network_score: float
    host_score: float
    final_score: float
    decision: str

    # 🔥 Explainability fields
    attack_type: str
    location: str
    severity: str
    reason: List[str]

    timestamp: str


# -----------------------------
# Detection Endpoint
# -----------------------------
@router.post(
    "/",
    response_model=DetectionResponse,
    summary="Run Hybrid Intrusion Detection"
)
def detect(request: DetectionRequest):

    try:
        # -----------------------------
        # Run detection pipeline
        # -----------------------------
        result = run_hybrid_detection(
            request.network_features,
            request.host_features
        )

        # -----------------------------
        # Construct full response
        # -----------------------------
        response = {
            "network_score": result.get("network_score", 0.0),
            "host_score": result.get("host_score", 0.0),
            "final_score": result.get("final_score", 0.0),
            "decision": result.get("decision", "Normal"),

            # 🔥 NEW FIELDS (CRITICAL)
            "attack_type": result.get("attack_type", "None"),
            "location": result.get("location", "None"),
            "severity": result.get("severity", "LOW"),
            "reason": result.get("reason", ["No anomaly detected"]),

            # Timestamp for UI
            "timestamp": datetime.utcnow().isoformat()
        }

        return response

    # -----------------------------
    # Error Handling
    # -----------------------------
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Detection failed: {e}")