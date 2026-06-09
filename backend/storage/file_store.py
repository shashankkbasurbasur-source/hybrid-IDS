"""backend/storage/file_store.py"""
import json, threading
from pathlib import Path
from backend.core.logger import get_logger

logger = get_logger(__name__)
_LOG_PATH = Path(__file__).resolve().parent.parent.parent / "logs" / "alerts.jsonl"
_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


class FileAlertLogger:
    def __init__(self):
        self._lock = threading.Lock()

    def log(self, alert: dict):
        with self._lock:
            with open(_LOG_PATH, "a") as f:
                f.write(json.dumps(alert) + "\n")

    def read_recent(self, n: int = 100) -> list:
        if not _LOG_PATH.exists():
            return []
        with self._lock:
            lines = _LOG_PATH.read_text().splitlines()
        return [json.loads(l) for l in lines[-n:] if l.strip()]


file_logger = FileAlertLogger()