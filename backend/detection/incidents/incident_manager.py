"""
Incident Manager — Modules 3 & 5.
Owns incident creation and the full lifecycle state machine:
NEW -> ACTIVE -> ACKNOWLEDGED -> INVESTIGATING -> RESOLVED -> CLOSED.
"""

import uuid
from datetime import datetime, timezone

from backend.config import INCIDENT_STATES
from backend.storage.db_store import (
    create_incident, update_incident, fetch_incident_by_id,
    insert_incident_history, insert_incident_note,
    link_alert_to_incident, update_alert_incident,
)
from backend.core.logger import get_logger

logger = get_logger(__name__)


class IncidentTransitionError(Exception):
    pass


# Only these forward transitions are allowed (Module 5)
ALLOWED_TRANSITIONS = {
    "NEW": {"ACTIVE", "ACKNOWLEDGED"},
    "ACTIVE": {"ACKNOWLEDGED", "INVESTIGATING"},
    "ACKNOWLEDGED": {"INVESTIGATING", "RESOLVED"},
    "INVESTIGATING": {"RESOLVED"},
    "RESOLVED": {"CLOSED", "INVESTIGATING"},  # allow reopening if resolved prematurely
    "CLOSED": set(),  # terminal
}


class IncidentManager:

    def create_from_alert(self, alert: dict) -> dict:
        now = alert.get("timestamp") or datetime.now(timezone.utc).isoformat()
        incident_id = str(uuid.uuid4())

        incident = {
            "incident_id": incident_id,
            "title": f"{alert['attack_type']} from {alert['source_ip']}",
            "status": "NEW",
            "severity": alert["severity"],
            "risk_level": alert["risk_level"],
            "attack_type": alert["attack_type"],
            "source_ip": alert["source_ip"],
            "dest_ip": alert["dest_ip"],
            "alert_count": 1,
            "created_at": now,
            "updated_at": now,
            "analyst": None,
            "fusion_type": "NIDS_ONLY",  # Fusion Engine upgrades this if HIDS correlates in
        }

        create_incident(incident)
        update_alert_incident(alert["alert_id"], incident_id)
        link_alert_to_incident(incident_id, alert["alert_id"])

        self._record_history(incident_id, "CREATED", None, "NEW", actor="system")

        logger.info(f"Incident created: {incident_id} ({incident['title']})")
        return incident

    def transition(self, incident_id: str, new_status: str, actor: str = "system"):
        if new_status not in INCIDENT_STATES:
            raise IncidentTransitionError(f"Unknown status '{new_status}'")

        incident = fetch_incident_by_id(incident_id)
        if incident is None:
            raise IncidentTransitionError(f"Incident '{incident_id}' not found")

        current_status = incident["status"]
        allowed = ALLOWED_TRANSITIONS.get(current_status, set())

        if new_status != current_status and new_status not in allowed:
            raise IncidentTransitionError(
                f"Cannot transition incident from '{current_status}' to '{new_status}'"
            )

        now = datetime.now(timezone.utc).isoformat()
        updates = {"status": new_status, "updated_at": now}
        if new_status in ("RESOLVED", "CLOSED"):
            updates["closed_at"] = now

        update_incident(incident_id, updates)
        self._record_history(incident_id, "STATUS_CHANGE", current_status, new_status, actor)

        logger.info(f"Incident {incident_id} transitioned: {current_status} -> {new_status} (by {actor})")
        return fetch_incident_by_id(incident_id)

    def acknowledge(self, incident_id: str, actor: str = "analyst"):
        return self.transition(incident_id, "ACKNOWLEDGED", actor)

    def investigate(self, incident_id: str, actor: str = "analyst"):
        return self.transition(incident_id, "INVESTIGATING", actor)

    def resolve(self, incident_id: str, actor: str = "analyst"):
        return self.transition(incident_id, "RESOLVED", actor)

    def close(self, incident_id: str, actor: str = "analyst"):
        return self.transition(incident_id, "CLOSED", actor)

    def add_note(self, incident_id: str, note: str, analyst: str = "analyst"):
        entry = {
            "incident_id": incident_id,
            "note": note,
            "analyst": analyst,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        insert_incident_note(entry)
        self._record_history(incident_id, "NOTE_ADDED", None, None, analyst)
        return entry

    def assign_analyst(self, incident_id: str, analyst: str):
        update_incident(incident_id, {"analyst": analyst, "updated_at": datetime.now(timezone.utc).isoformat()})
        self._record_history(incident_id, "ASSIGNED", None, None, analyst)

    def _record_history(self, incident_id, event, old_status, new_status, actor):
        insert_incident_history({
            "incident_id": incident_id,
            "event": event,
            "old_status": old_status,
            "new_status": new_status,
            "actor": actor,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })


incident_manager = IncidentManager()