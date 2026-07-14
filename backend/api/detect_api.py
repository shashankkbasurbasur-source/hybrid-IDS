"""
Detection API - RESTful Interface for Hybrid IDS
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

from backend.detection.service import run_hybrid_detection
from backend.storage.db_store import fetch_latest_network_statistics, fetch_flows, fetch_recent_packets, fetch_protocol_statistics, count_packets

router = APIRouter()


class DetectionRequest(BaseModel):
    network_features: List[float] = Field(..., description="NIDS feature vector")
    host_features: List[float] = Field(..., description="HIDS feature vector")
    network_context: Optional[dict] = Field(None, description="Network metadata")
    host_context: Optional[dict] = Field(None, description="Host metadata")


class DetectionResponse(BaseModel):
    network_score: float
    host_score: float
    final_score: float
    decision: str
    attack_type: str
    attack_domain: str
    location: str
    severity: str
    confidence: float
    reason: List[str]
    threat_intelligence: dict
    triggered_by: List[str]
    timestamp: str
    alert: dict


@router.post("/", response_model=DetectionResponse)
def detect(request: DetectionRequest):
    """Run hybrid intrusion detection"""
    
    try:
        result = run_hybrid_detection(
            request.network_features,
            request.host_features,
            request.network_context,
            request.host_context
        )
        
        response = {
            "network_score": result["network_score"],
            "host_score": result["host_score"],
            "final_score": result["final_score"],
            "decision": result["decision"],
            "attack_type": result["attack_type"],
            "attack_domain": result["attack_domain"],
            "location": result["location"],
            "severity": result["severity"],
            "confidence": result["confidence"],
            "reason": result["reason"],
            "threat_intelligence": result.get("threat_intelligence", {}),
            "triggered_by": result["triggered_by"],
            "timestamp": datetime.utcnow().isoformat(),
            "alert": result["alert"]
        }
        
        return response
    
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Detection failed: {str(e)}")


@router.get("/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "running",
        "service": "Hybrid IDS Detection API",
        "timestamp": datetime.utcnow().isoformat()
    }

@router.get("/status")
def get_nids_status():
    stats = fetch_latest_network_statistics() or {}
    total_packets = count_packets()
    return {
        "status": "operational" if total_packets > 0 else "idle",
        "packets_captured": total_packets,
        "active_flows": stats.get("active_flows", 0),
        "last_update": stats.get("timestamp", datetime.utcnow().isoformat())
    }

@router.get("/flows")
def get_nids_flows(limit: int = 50):
    return {"flows": fetch_flows(limit)}

@router.get("/packets")
def get_nids_packets(limit: int = 50):
    return {"packets": fetch_recent_packets(limit)}

@router.get("/protocols")
def get_protocols():
    stats = fetch_protocol_statistics()
    return {row["protocol"]: row["packets"] for row in stats} if stats else {}