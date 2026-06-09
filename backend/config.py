# backend/config.py

"""
Runtime configuration — override via environment variables.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings:
    APP_NAME         : str  = "Hybrid IDS"
    VERSION          : str  = "2.0.0"
    DEBUG            : bool = os.getenv("IDS_DEBUG", "false").lower() == "true"
    HOST             : str  = os.getenv("IDS_HOST", "127.0.0.1")
    PORT             : int  = int(os.getenv("IDS_PORT", "8000"))

    # Model paths (override via env if needed)
    MODEL_DIR        : Path = BASE_DIR / "models"

    # Storage
    STORAGE_DIR      : Path = BASE_DIR / "storage"
    DB_PATH          : Path = STORAGE_DIR / "alerts.db"

    # Live capture
    PACKET_COUNT     : int  = int(os.getenv("IDS_PACKET_COUNT", "10"))
    CAPTURE_INTERFACE: str  = os.getenv("IDS_INTERFACE", None)

settings = Settings()