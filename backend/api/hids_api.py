"""
HIDS API Endpoints
"""

from fastapi import APIRouter, File, UploadFile, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

from backend.ingestions.hids_ingestor import hids_ingestor

router = APIRouter()


class HIDSStatusResponse(BaseModel):
    mode: str
    is_running: bool
    log_file: Optional[str]
    events_parsed: int
    sessions_active: int
    detections: int


class ManualAnalysisRequest(BaseModel):
    log_content: str


@router.get("/status")
def get_status():
    """Get HIDS status"""
    
    status = hids_ingestor.get_status()
    
    return {
        "mode": status["mode"],
        "is_running": status["is_running"],
        "log_file": status["log_monitor"]["log_file"],
        "monitoring": status["log_monitor"]["is_monitoring"],
        "events_parsed": status["stats"]["events_parsed"],
        "sessions_active": status["event_builder"]["sessions_active"],
        "detections": status["stats"]["detections"],
        "alerts": status["stats"]["alerts"],
        "timestamp": datetime.utcnow().isoformat()
    }


@router.post("/start-monitoring")
def start_monitoring():
    """Start live log monitoring"""
    
    success = hids_ingestor.start_live_monitoring()
    
    if success:
        return {
            "status": "success",
            "message": "Live monitoring started",
            "log_file": hids_ingestor.log_monitor.log_file
        }
    else:
        raise HTTPException(
            status_code=500,
            detail="Failed to start monitoring. Log file not accessible."
        )


@router.post("/stop-monitoring")
def stop_monitoring():
    """Stop live log monitoring"""
    
    hids_ingestor.stop_live_monitoring()
    
    return {
        "status": "success",
        "message": "Live monitoring stopped"
    }


@router.post("/analyze-manual")
async def analyze_manual(file: UploadFile = File(...)):
    """Analyze uploaded log file manually"""
    
    try:
        # Read file content
        content = await file.read()
        log_text = content.decode('utf-8', errors='ignore')
        
        # Save temporarily
        temp_path = f"/tmp/{file.filename}"
        with open(temp_path, 'w') as f:
            f.write(log_text)
        
        # Analyze
        detections = hids_ingestor.analyze_manual_log(temp_path)
        
        return {
            "status": "success",
            "file_name": file.filename,
            "lines_analyzed": len(log_text.split('\n')),
            "events_parsed": hids_ingestor.stats["events_parsed"],
            "detections_count": len(detections),
            "detections": detections,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Error analyzing file: {str(e)}"
        )


@router.get("/active-sessions")
def get_active_sessions():
    """Get active authentication sessions"""
    
    sessions = hids_ingestor.get_active_sessions()
    
    return {
        "count": len(sessions),
        "sessions": sessions,
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/detections")
def get_detections(limit: int = 50):
    """Get recent detections"""
    
    detections = hids_ingestor.get_recent_detections(limit)
    
    return {
        "count": len(detections),
        "detections": detections,
        "timestamp": datetime.utcnow().isoformat()
    }