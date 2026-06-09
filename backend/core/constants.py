# backend/core/constants.py

"""
Global configuration constants for Hybrid IDS
"""

from pathlib import Path

# ── Project root ──────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# ── Model paths ───────────────────────────────────
MODEL_DIR          = BASE_DIR / "models"
NIDS_MODEL_PATH    = MODEL_DIR / "random_forest_model.pkl"
HIDS_MODEL_PATH    = MODEL_DIR / "hids_model.pkl"
SCALER_PATH        = MODEL_DIR / "scaler.pkl"

# ── Fusion weights ────────────────────────────────
FUSION_NETWORK_WEIGHT = 0.6
FUSION_HOST_WEIGHT    = 0.4

# ── Decision threshold ────────────────────────────
DECISION_THRESHOLD    = 0.4

# ── Strong-signal overrides ───────────────────────
STRONG_NIDS_THRESHOLD = 0.75
STRONG_HIDS_THRESHOLD = 0.60

# ── Alert severity thresholds ─────────────────────
HIGH_SEVERITY_THRESHOLD   = 0.80
MEDIUM_SEVERITY_THRESHOLD = 0.55

# ── SSH rule thresholds ───────────────────────────
SSH_FAIL_HIGH_THRESHOLD   = 5
SSH_FAIL_MEDIUM_THRESHOLD = 2

# ── Storage ───────────────────────────────────────
ALERT_STORE_PATH = BASE_DIR / "storage" / "alerts.json"
MAX_STORED_ALERTS = 1000