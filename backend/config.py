"""
Central configuration for Hybrid IDS.
NOTE: Feature order/count is NO LONGER configured here — it's loaded at
runtime from models/feature_metadata.json (saved during training) via
backend/detection/features/feature_metadata.py. This file only holds
values that are genuinely operator-configurable.
"""

from pathlib import Path

MODEL_DIR = Path("models")

FEATURE_VERSION = "v1"

MODEL_PATH = MODEL_DIR / "random_forest_model.pkl"
SCALER_PATH = MODEL_DIR / "scaler.pkl"
MODEL_NAME = "NIDS_RandomForest"
MODEL_VERSION = "1.0"

CONFIDENCE_THRESHOLD = 0.5

SEVERITY_THRESHOLDS = {
    "CRITICAL": 0.90,
    "HIGH": 0.75,
    "MEDIUM": 0.50,
    "LOW": 0.0,
}

PROTOCOL_NUMERIC_MAP = {
    "TCP": 6, "UDP": 17, "ICMP": 1, "ARP": 0, "DNS": 6, "DHCP": 17,
    "HTTP": 6, "HTTPS": 6, "FTP": 6, "SSH": 6, "SMTP": 6, "NTP": 17,
    "OTHER": -1,
}

DIRECTION_NUMERIC_MAP = {
    "incoming": 0, "outgoing": 1, "internal": 2, "unknown": -1,
}

# -----------------------------
# Alert / Incident / Fusion configuration
# -----------------------------
CORRELATION_WINDOW_SECONDS = 120     # merge alerts within this window
RISK_LEVEL_THRESHOLDS = {
    "CRITICAL": 0.90,
    "HIGH": 0.75,
    "MEDIUM": 0.50,
    "LOW": 0.0,
}

ALERT_LIFECYCLE_STATES = ["NEW", "ACTIVE", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "CLOSED"]
INCIDENT_STATES = ["NEW", "ACTIVE", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "CLOSED"]

FEATURE_QUEUE_SIZE = 10000
DETECTION_QUEUE_SIZE = 10000
ALERT_QUEUE_SIZE = 10000
PREDICTION_WORKER_COUNT = 2