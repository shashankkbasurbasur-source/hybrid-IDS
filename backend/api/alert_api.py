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
    incidents = fetch_incidents(limit, status)
    for inc in incidents:
        inc["alert_id"] = inc.pop("incident_id", None)
    return {"incidents": incidents}


@router.get("/incidents/{alert_id}")
def get_incident(alert_id: str):
    incident = fetch_incident_by_id(alert_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")

    incident["alert_id"] = incident.pop("incident_id", None)
    return {
        **incident,
        "alerts": fetch_incident_alerts(alert_id),
        "history": fetch_incident_history(alert_id),
        "notes": fetch_incident_notes(alert_id),
    }


class NoteRequest(BaseModel):
    note: str
    analyst: str = "analyst"


class AssignRequest(BaseModel):
    analyst: str


@router.post("/incident/{alert_id}/ack")
def acknowledge_incident(alert_id: str, actor: str = "analyst"):
    try:
        return incident_manager.acknowledge(alert_id, actor)
    except IncidentTransitionError as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.post("/incident/{alert_id}/investigate")
def investigate_incident(alert_id: str, actor: str = "analyst"):
    try:
        return incident_manager.investigate(alert_id, actor)
    except IncidentTransitionError as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.post("/incident/{alert_id}/resolve")
def resolve_incident(alert_id: str, actor: str = "analyst"):
    try:
        return incident_manager.resolve(alert_id, actor)
    except IncidentTransitionError as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.post("/incident/{alert_id}/close")
def close_incident(alert_id: str, actor: str = "analyst"):
    try:
        return incident_manager.close(alert_id, actor)
    except IncidentTransitionError as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.post("/incident/{alert_id}/note")
def add_incident_note(alert_id: str, request: NoteRequest):
    if fetch_incident_by_id(alert_id) is None:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    return incident_manager.add_note(alert_id, request.note, request.analyst)


@router.post("/incident/{alert_id}/assign")
def assign_incident(alert_id: str, request: AssignRequest):
    if fetch_incident_by_id(alert_id) is None:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    incident_manager.assign_analyst(alert_id, request.analyst)
    return fetch_incident_by_id(alert_id)