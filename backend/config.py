"""
Global Configuration for Hybrid IDS
"""

import os
from pathlib import Path

# Project root
BASE_DIR = Path(__file__).resolve().parent.parent

# Model paths
MODEL_DIR = BASE_DIR / "models"
NIDS_MODEL_PATH = MODEL_DIR / "random_forest_model.pkl"
HIDS_MODEL_PATH = MODEL_DIR / "hids_model.pkl"
SCALER_PATH = MODEL_DIR / "scaler.pkl"

# Network settings
NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", None)  # Auto-detect if None
PACKET_TIMEOUT = 30
MIN_PACKETS_FOR_FLOW = 5

# Log monitoring
ENABLE_LOG_MONITORING = True
LOG_PATHS = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/syslog"
]

# Alert thresholds
NIDS_THRESHOLD = 0.5
HIDS_THRESHOLD = 0.6
FUSION_THRESHOLD = 0.55

# Fusion weights
FUSION_NETWORK_WEIGHT = 0.6
FUSION_HOST_WEIGHT = 0.4

# Severity thresholds
CRITICAL_THRESHOLD = 0.85
HIGH_THRESHOLD = 0.70
MEDIUM_THRESHOLD = 0.40

# API settings
API_HOST = "0.0.0.0"
API_PORT = 8000
API_RELOAD = True

# Feature vector sizes
NIDS_FEATURE_SIZE = 78
HIDS_FEATURE_SIZE = 100