"""
Alert Generator — Module 1.
Converts a stored ML prediction into a structured Alert with lifecycle
state, risk level, and a correlation key for downstream merging.
"""

import uuid
from datetime import datetime, timezone

from backend.config import RISK_LEVEL_THRESHOLDS
from backend.storage.db_store import insert_alert
from backend.core.logger import get_logger

logger = get_logger(__name__)


class AlertGenerator:

    def _risk_level(self, confidence: float) -> str:
        for level, threshold in RISK_LEVEL_THRESHOLDS.items():
            if confidence >= threshold:
                return level
        return "LOW"

    def _correlation_key(self, prediction: dict, flow: dict) -> str:
        """
        Groups alerts that likely represent the SAME ongoing activity:
        same source, same destination, same attack type. Time-window
        matching happens separately in AlertCorrelator.
        """
        return "|".join(str(x) for x in (
            flow.get("src_ip"), flow.get("dst_ip"), prediction.get("attack_type")
        ))

    def generate(self, prediction_with_flow: dict) -> dict | None:
        """
        Returns the created alert dict, or None if the prediction was
        Normal (no alert generated for benign traffic).
        """
        if prediction_with_flow.get("prediction") != "Attack":
            return None

        flow = prediction_with_flow.get("flow", {})
        now = datetime.now(timezone.utc).isoformat()

        alert = {
            "alert_id": str(uuid.uuid4()),
            "timestamp": now,
            "severity": prediction_with_flow.get("severity", "LOW"),
            "confidence": prediction_with_flow.get("confidence", 0.0),
            "source_ip": flow.get("src_ip"),
            "dest_ip": flow.get("dst_ip"),
            "protocol": flow.get("protocol"),
            "attack_type": prediction_with_flow.get("attack_type", "Unknown"),
            "status": "NEW",
            "prediction_id": prediction_with_flow.get("prediction_id"),
            "flow_id": flow.get("flow_id"),
            "flow_key": flow.get("flow_key"),
            "risk_level": self._risk_level(prediction_with_flow.get("confidence", 0.0)),
            "source": "NIDS",  # Step 6 will also produce "HIDS" alerts through this same generator
            "incident_id": None,   # set by AlertCorrelator/IncidentManager after creation
            "correlation_key": self._correlation_key(prediction_with_flow, flow),
        }

        try:
            insert_alert(alert)
        except Exception as e:
            logger.error(f"Failed to store alert {alert['alert_id']}: {e}")
            return None

        logger.info(
            f"Alert generated: {alert['alert_id']} ({alert['attack_type']}, "
            f"{alert['severity']}, {alert['source_ip']} -> {alert['dest_ip']})"
        )
        return alert


alert_generator = AlertGenerator()