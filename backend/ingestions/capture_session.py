"""
Capture Session Tracker
Every start/stop of the capture engine is recorded as a session with
full timing and throughput summary, for later reporting/investigation.
"""

import uuid
from datetime import datetime, timezone

from backend.storage.db_store import create_session, finalize_session
from backend.core.logger import get_logger

logger = get_logger(__name__)


class CaptureSession:
    def __init__(self, interface: str):
        self.session_id = str(uuid.uuid4())
        self.interface = interface
        self.start_time = datetime.now(timezone.utc)
        self.stop_time = None

    def persist_start(self):
        create_session({
            "session_id": self.session_id,
            "interface": self.interface,
            "start_time": self.start_time.isoformat(),
            "status": "RUNNING",
        })
        logger.info(f"Capture session started: {self.session_id} on {self.interface}")

    def finalize(self, total_packets: int, total_bytes: int, status: str = "STOPPED"):
        self.stop_time = datetime.now(timezone.utc)
        duration = max((self.stop_time - self.start_time).total_seconds(), 0.001)

        stats = {
            "stop_time": self.stop_time.isoformat(),
            "duration_seconds": round(duration, 2),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "avg_pps": round(total_packets / duration, 2),
            "avg_bps": round(total_bytes / duration, 2),
            "status": status,
        }

        finalize_session(self.session_id, stats)
        logger.info(f"Capture session finalized: {self.session_id} ({status}), stats={stats}")
        return stats