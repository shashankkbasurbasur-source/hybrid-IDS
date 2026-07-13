"""
Alert Correlator — Modules 2 & 6.
Merges alerts that represent the same underlying activity (same source IP,
destination IP, attack type, within a time window) into a single incident
rather than flooding the dashboard with duplicates.
"""

from backend.config import CORRELATION_WINDOW_SECONDS
from backend.storage.db_store import (
    fetch_open_incident_by_correlation, update_alert_incident,
    link_alert_to_incident, update_incident,
)
from backend.core.logger import get_logger

logger = get_logger(__name__)


class AlertCorrelator:
    """
    Correlation dimensions (per spec): Source IP, Destination IP, Time
    Window, Attack Type — all folded into AlertGenerator's correlation_key.
    'Same Device' / 'Same User (HIDS)' correlation activates once Step 6
    produces HIDS alerts with device/user identifiers; the correlation_key
    scheme is designed to extend to those fields without restructuring.
    """

    def correlate(self, alert: dict):
        """
        Returns the incident_id this alert was attached to — either an
        existing matching incident (bumping its alert_count) or None,
        signaling the caller (IncidentManager) to create a new incident.
        """
        existing = fetch_open_incident_by_correlation(
            alert["correlation_key"], CORRELATION_WINDOW_SECONDS
        )

        if existing is None:
            return None

        incident_id = existing["incident_id"]
        update_alert_incident(alert["alert_id"], incident_id)
        link_alert_to_incident(incident_id, alert["alert_id"])
        update_incident(incident_id, {
            "alert_count": existing["alert_count"] + 1,
            "updated_at": alert["timestamp"],
            # Escalate severity if this new alert is more severe than the incident's current level
            "severity": self._higher_severity(existing["severity"], alert["severity"]),
        })

        logger.info(
            f"Alert {alert['alert_id']} correlated into existing incident "
            f"{incident_id} (now {existing['alert_count'] + 1} alerts)"
        )
        return incident_id

    def _higher_severity(self, current: str, new: str) -> str:
        order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        try:
            return new if order.index(new) > order.index(current) else current
        except ValueError:
            return current


alert_correlator = AlertCorrelator()