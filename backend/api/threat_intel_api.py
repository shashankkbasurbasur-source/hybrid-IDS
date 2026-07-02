"""
Threat Intelligence API
REST endpoints for threat analysis
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from backend.intelligence.threat_intel_service import threat_intel_service

router = APIRouter()


class ThreatReportResponse(BaseModel):
    report_id: str
    incident_id: str
    attack_type: str
    attack_stage: str
    severity: str
    confidence: float


@router.get("/report/{incident_id}")
def get_threat_report(incident_id: str):
    """Get threat intelligence report for incident"""
    
    report = threat_intel_service.get_report(incident_id)
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    return report


@router.get("/report/{incident_id}/export")
def export_threat_report(incident_id: str, format: str = Query("json", regex="^(json|text|html)$")):
    """Export threat report in specified format"""
    
    exported = threat_intel_service.export_report(incident_id, format)
    
    if not exported:
        raise HTTPException(status_code=404, detail="Report not found")
    
    return {
        "incident_id": incident_id,
        "format": format,
        "data": exported,
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/iocs")
def search_iocs(value: str):
    """Search for incidents by IOC"""
    
    result = threat_intel_service.search_iocs(value)
    
    if not result:
        raise HTTPException(status_code=404, detail="No incidents found for IOC")
    
    return result


@router.get("/history")
def get_threat_history(
    source_ip: Optional[str] = None,
    username: Optional[str] = None
):
    """Get threat history for indicators"""
    
    history = threat_intel_service.get_threat_history(source_ip, username)
    
    return {
        "query": {
            "source_ip": source_ip,
            "username": username
        },
        "results": history,
        "timestamp": datetime.utcnow().isoformat()
    }