"""
Alert & Incident API — Module 8.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.storage.db_store import (
    fetch_alerts, fetch_alert_by_id, fetch_alert_severity_distribution,
    fetch_incidents, fetch_incident_by_id, fetch_incident_history,
    fetch_incident_notes, fetch_incident_alerts,
)
from backend.detection.incidents.incident_manager import incident_manager, IncidentTransitionError

router = APIRouter()


# -----------------------------
# Alerts
# -----------------------------
@router.get("/alerts")
def get_alerts(limit: int = 100, status: str = None):
    return {"alerts": fetch_alerts(limit, status)}


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    alert = fetch_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    return alert


@router.get("/alerts/severity/distribution")
def alert_severity_distribution():
    return {"distribution": fetch_alert_severity_distribution()}


# -----------------------------
# Incidents
# -----------------------------
@router.get("/incidents")
def get_incidents(limit: int = 100, status: str = None):
    return {"incidents": fetch_incidents(limit, status)}


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    incident = fetch_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")

    return {
        **incident,
        "alerts": fetch_incident_alerts(incident_id),
        "history": fetch_incident_history(incident_id),
        "notes": fetch_incident_notes(incident_id),
    }


class NoteRequest(BaseModel):
    note: str
    analyst: str = "analyst"


class AssignRequest(BaseModel):
    analyst: str


@router.post("/incident/{incident_id}/ack")
def acknowledge_incident(incident_id: str, actor: str = "analyst"):
    try:
        return incident_manager.acknowledge(incident_id, actor)
    except IncidentTransitionError as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.post("/incident/{incident_id}/investigate")
def investigate_incident(incident_id: str, actor: str = "analyst"):
    try:
        return incident_manager.investigate(incident_id, actor)
    except IncidentTransitionError as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.post("/incident/{incident_id}/resolve")
def resolve_incident(incident_id: str, actor: str = "analyst"):
    try:
        return incident_manager.resolve(incident_id, actor)
    except IncidentTransitionError as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.post("/incident/{incident_id}/close")
def close_incident(incident_id: str, actor: str = "analyst"):
    try:
        return incident_manager.close(incident_id, actor)
    except IncidentTransitionError as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.post("/incident/{incident_id}/note")
def add_incident_note(incident_id: str, request: NoteRequest):
    if fetch_incident_by_id(incident_id) is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return incident_manager.add_note(incident_id, request.note, request.analyst)


@router.post("/incident/{incident_id}/assign")
def assign_incident(incident_id: str, request: AssignRequest):
    if fetch_incident_by_id(incident_id) is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    incident_manager.assign_analyst(incident_id, request.analyst)
    return fetch_incident_by_id(incident_id)