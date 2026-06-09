"""backend/storage/db_store.py"""
import json, sqlite3, threading
from pathlib import Path
from typing import Optional
from backend.core.logger import get_logger

logger = get_logger(__name__)

_DB_PATH = Path(__file__).resolve().parent.parent.parent / "logs" / "alerts.db"
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

_CREATE = '''
CREATE TABLE IF NOT EXISTS alerts (
    alert_id   TEXT PRIMARY KEY,
    timestamp  TEXT NOT NULL,
    decision   TEXT NOT NULL,
    severity   TEXT NOT NULL,
    confidence REAL NOT NULL,
    raw_json   TEXT NOT NULL
);
'''

_INSERT = '''
INSERT OR REPLACE INTO alerts
    (alert_id, timestamp, decision, severity, confidence, raw_json)
VALUES (:alert_id, :timestamp, :type, :severity, :confidence, :raw_json);
'''


class AlertStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(_CREATE)
        self._conn.commit()
        logger.info("AlertStore ready at %s", _DB_PATH)
        
    def verify_storage(self) -> dict:
        """
        Verify that alerts are being stored correctly.
        Returns storage status for debugging.
        """
        try:
            with self._lock:
                # Count total alerts
                result = self._conn.execute("SELECT COUNT(*) as cnt FROM alerts").fetchone()
                total = result["cnt"] if result else 0
                
                # Get latest alert
                latest = self._conn.execute(
                    "SELECT alert_id, timestamp, severity, decision "
                    "FROM alerts ORDER BY timestamp DESC LIMIT 1"
                ).fetchone()
                
                # Get alert counts by severity
                severity_counts = self._conn.execute(
                    "SELECT severity, COUNT(*) as cnt FROM alerts "
                    "GROUP BY severity ORDER BY cnt DESC"
                ).fetchall()
                
                return {
                    "status": "OK" if total > 0 else "Empty",
                    "total_alerts": total,
                    "latest_alert": dict(latest) if latest else None,
                    "by_severity": {row["severity"]: row["cnt"] for row in severity_counts},
                    "db_path": str(_DB_PATH),
                }
        except Exception as e:
            logger.error("Storage verification failed: %s", e)
            return {
                "status": "ERROR",
                "error": str(e),
                "db_path": str(_DB_PATH),
            }    

    def save(self, alert: dict):
        try:
            row = {**alert, "raw_json": json.dumps(alert)}
            with self._lock:
                self._conn.execute(_INSERT, row)
                self._conn.commit()
                self._trim()
        except Exception as e:
            logger.warning("AlertStore.save failed: %s", e)

    def _trim(self):
        self._conn.execute(
            "DELETE FROM alerts WHERE alert_id NOT IN "
            "(SELECT alert_id FROM alerts ORDER BY timestamp DESC LIMIT 10000)"
        )
        self._conn.commit()

    def get_all(self, limit: int = 500, severity: Optional[str] = None) -> list:
        q, p = "SELECT raw_json FROM alerts", []
        if severity:
            q += " WHERE severity = ?"
            p.append(severity.upper())
        q += " ORDER BY timestamp DESC LIMIT ?"
        p.append(limit)
        with self._lock:
            rows = self._conn.execute(q, p).fetchall()
        return [json.loads(r["raw_json"]) for r in rows]

    def get_by_id(self, alert_id: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT raw_json FROM alerts WHERE alert_id=?", (alert_id,)
            ).fetchone()
        return json.loads(row["raw_json"]) if row else None

    def stats(self) -> dict:
        with self._lock:
            rows = self._conn.execute(
                "SELECT severity, decision, COUNT(*) as cnt "
                "FROM alerts GROUP BY severity, decision"
            ).fetchall()
        result = {"total": 0, "by_severity": {}, "by_decision": {}}
        for r in rows:
            result["total"] += r["cnt"]
            result["by_severity"][r["severity"]] = result["by_severity"].get(r["severity"], 0) + r["cnt"]
            result["by_decision"][r["decision"]] = result["by_decision"].get(r["decision"], 0) + r["cnt"]
        return result

    def close(self):
        self._conn.close()


alert_store = AlertStore()