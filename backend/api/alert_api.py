"""
Alert Management API
REST endpoints for alert operations
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

from backend.detection.fusion_service import fusion_service
from backend.storage.nids_store import nids_db

router = APIRouter()


class IncidentNoteRequest(BaseModel):
    analyst: str
    note: str


class IncidentActionRequest(BaseModel):
    analyst: str


class AlertResponse(BaseModel):
    incident_id: str
    decision: str
    severity: str
    attack_type: str
    confidence: float


@router.get("/incidents")
def get_incidents(limit: int = Query(50, ge=1, le=500)):
    """Get active incidents"""
    
    incidents = fusion_service.get_active_incidents(limit)
    
    return {
        "count": len(incidents),
        "incidents": incidents,
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    """Get specific incident"""
    
    incident = fusion_service.get_incident(incident_id)
    
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    return incident


@router.post("/incidents/{incident_id}/acknowledge")
def acknowledge_incident(incident_id: str, request: IncidentActionRequest):
    """Acknowledge incident"""
    
    success = fusion_service.acknowledge_incident(
        incident_id, request.analyst
    )
    
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    return {
        "status": "success",
        "incident_id": incident_id,
        "action": "acknowledged"
    }


@router.post("/incidents/{incident_id}/resolve")
def resolve_incident(incident_id: str, request: IncidentActionRequest):
    """Resolve incident"""
    
    success = fusion_service.resolve_incident(
        incident_id, request.analyst
    )
    
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    return {
        "status": "success",
        "incident_id": incident_id,
        "action": "resolved"
    }


@router.post("/incidents/{incident_id}/notes")
def add_incident_note(incident_id: str, request: IncidentNoteRequest):
    """Add note to incident"""
    
    success = fusion_service.add_incident_note(
        incident_id, request.analyst, request.note
    )
    
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    return {
        "status": "success",
        "incident_id": incident_id,
        "action": "note_added"
    }


@router.get("/alerts")
def get_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500)
):
    """Get alerts with filtering"""
    
    alerts = nids_db.get_recent_alerts(limit)
    
    # Filter by severity if provided
    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity]
    
    # Filter by status if provided
    if status:
        alerts = [a for a in alerts if a.get("status") == status]
    
    return {
        "count": len(alerts),
        "alerts": alerts,
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/statistics")
def get_statistics():
    """Get fusion service statistics"""
    
    stats = fusion_service.get_statistics()
    db_stats = nids_db.get_capture_stats()
    
    return {
        "fusion": stats,
        "database": db_stats,
        "timestamp": datetime.utcnow().isoformat()
    }