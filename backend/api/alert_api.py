"""backend/api/alert_api.py"""
from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from backend.storage.db_store import alert_store
from backend.core.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()

@router.get("/", summary="List recent alerts")
def list_alerts(
    limit:    int           = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None),
):
    try:
        return {"count": 0, "alerts": alert_store.get_all(limit=limit, severity=severity)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/stats", summary="Alert statistics")
def alert_stats():
    try:
        return alert_store.stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{alert_id}", summary="Get alert by ID")
def get_alert(alert_id: str):
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert not found")
    return alert

@router.get("/verify", summary="Verify alert storage")
def verify_storage():
    """Verify that alerts are being stored and retrieved correctly."""
    try:
        return alert_store.verify_storage()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))