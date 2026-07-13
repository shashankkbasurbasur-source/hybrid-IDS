import sqlite3, json, os

DB_PATH = os.path.join("storage", "hids_incidents.db")


def _get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY, timestamp TEXT, source_ip TEXT, attack_type TEXT,
            severity TEXT, confidence REAL, auth_score REAL, syscall_score REAL,
            mitre_technique TEXT, mitre_tactic TEXT, recommendation TEXT, feature_vector TEXT
        )
    """)
    return conn


def log_incident(alert: dict, feature_vector: list = None):
    conn = _get_connection()
    with conn:
        conn.execute(
            """INSERT OR REPLACE INTO incidents
               (id, timestamp, source_ip, attack_type, severity, confidence,
                auth_score, syscall_score, mitre_technique, mitre_tactic, recommendation, feature_vector)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (alert["id"], alert["timestamp"], alert["source_ip"], alert["attack_type"],
             alert["severity"], alert["confidence"], alert.get("auth_score"), alert.get("syscall_score"),
             alert["mitre_technique"], alert["mitre_tactic"], alert["recommendation"],
             json.dumps(feature_vector) if feature_vector is not None else None),
        )
    conn.close()


def get_recent_incidents(limit: int = 50):
    conn = _get_connection()
    cur = conn.execute("SELECT * FROM incidents ORDER BY timestamp DESC LIMIT ?", (limit,))
    columns = [c[0] for c in cur.description]
    rows = [dict(zip(columns, row)) for row in cur.fetchall()]
    conn.close()
    return rows