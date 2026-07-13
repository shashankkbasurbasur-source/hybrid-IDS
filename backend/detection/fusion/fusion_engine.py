"""
Fusion Engine — Module 4.
Merges NIDS and HIDS alerts that correlate to the same underlying incident
(same source device / same time window) into a single Hybrid Incident.

CURRENT STATE: Only NIDS alerts exist until Step 6 implements HIDS. This
engine is fully wired and functional today — every incident it produces is
correctly marked NIDS_ONLY. When Step 6 starts pushing HIDS alerts through
the same AlertGenerator -> AlertCorrelator path, this engine's existing
try_fuse() logic activates automatically: no redesign needed here.
"""

from datetime import datetime, timezone

from backend.storage.db_store import (
    fetch_incident_by_id, update_incident, fetch_incident_alerts, insert_incident_history,
)
from backend.core.logger import get_logger

logger = get_logger(__name__)


class FusionEngine:

    def try_fuse(self, incident_id: str):
        """
        Inspects an incident's linked alerts. If both NIDS and HIDS sources
        are present, upgrades fusion_type to HYBRID and boosts severity —
        a confirmed multi-layer attack is higher confidence than either
        signal alone. Safe to call on every alert attach; no-ops if only
        one source is present (the common case until Step 6 exists).
        """
        alerts = fetch_incident_alerts(incident_id)
        if not alerts:
            return

        sources = {a.get("source", "NIDS") for a in alerts}

        if "NIDS" in sources and "HIDS" in sources:
            self._promote_to_hybrid(incident_id, alerts)
        elif "HIDS" in sources and "NIDS" not in sources:
            update_incident(incident_id, {"fusion_type": "HIDS_ONLY"})
        # else: NIDS_ONLY — already the default set at creation, nothing to do

    def _promote_to_hybrid(self, incident_id: str, alerts: list):
        incident = fetch_incident_by_id(incident_id)
        if incident is None or incident.get("fusion_type") == "HYBRID":
            return  # already fused, avoid duplicate history entries

        max_confidence = max((a.get("confidence") or 0.0) for a in alerts)
        escalated_severity = "CRITICAL" if max_confidence >= 0.75 else incident["severity"]

        update_incident(incident_id, {
            "fusion_type": "HYBRID",
            "severity": escalated_severity,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })

        insert_incident_history({
            "incident_id": incident_id,
            "event": "FUSED",
            "old_status": incident["fusion_type"],
            "new_status": "HYBRID",
            "actor": "fusion_engine",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        logger.info(
            f"Incident {incident_id} FUSED: NIDS + HIDS signals confirmed "
            f"-> severity escalated to {escalated_severity}"
        )


fusion_engine = FusionEngine()  