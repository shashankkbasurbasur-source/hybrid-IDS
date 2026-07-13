"""
SQLite storage layer for Hybrid IDS.
Single source of truth — no duplicate function definitions, no missing
tables. Creates the full schema (Steps 1-4) and runs all migrations
idempotently on every startup.
"""

import sqlite3
import threading
from pathlib import Path

from backend.core.logger import get_logger

logger = get_logger(__name__)

DB_PATH = Path("backend/storage/hybrid_ids.db")

_write_lock = threading.Lock()
_local = threading.local()


def get_connection():
    if not hasattr(_local, "conn"):
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys = ON")
    return _local.conn


# =========================================================
# SCHEMA — Step 2 core tables (packets table included!)
# =========================================================
SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    timestamp TEXT NOT NULL,
    interface TEXT,
    eth_src TEXT,
    eth_dst TEXT,
    ip_version INTEGER,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    length INTEGER,
    ttl INTEGER,
    flags INTEGER,
    dns_query TEXT,
    http_host TEXT,
    is_fragmented INTEGER DEFAULT 0,
    parse_error INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);
CREATE INDEX IF NOT EXISTS idx_packets_src_dst ON packets(src_ip, dst_ip);
CREATE INDEX IF NOT EXISTS idx_packets_session ON packets(session_id);

CREATE TABLE IF NOT EXISTS devices (
    ip TEXT PRIMARY KEY,
    mac TEXT,
    hostname TEXT,
    vendor TEXT,
    first_seen TEXT,
    last_seen TEXT,
    packet_count INTEGER DEFAULT 0,
    bytes_total INTEGER DEFAULT 0,
    status TEXT DEFAULT 'Online'
);

CREATE TABLE IF NOT EXISTS flows (
    flow_key TEXT PRIMARY KEY,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    first_seen TEXT,
    last_seen TEXT,
    packet_count INTEGER DEFAULT 0,
    byte_count INTEGER DEFAULT 0,
    fwd_packets INTEGER DEFAULT 0,
    bwd_packets INTEGER DEFAULT 0,
    status TEXT DEFAULT 'ACTIVE'
);

CREATE TABLE IF NOT EXISTS capture_sessions (
    session_id TEXT PRIMARY KEY,
    interface TEXT,
    start_time TEXT,
    stop_time TEXT,
    duration_seconds REAL,
    total_packets INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    avg_pps REAL DEFAULT 0,
    avg_bps REAL DEFAULT 0,
    status TEXT DEFAULT 'RUNNING'
);

CREATE TABLE IF NOT EXISTS capture_statistics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    timestamp TEXT,
    total_packets INTEGER,
    packets_per_sec REAL,
    bytes_per_sec REAL,
    total_bytes INTEGER,
    active_flows INTEGER,
    active_devices INTEGER,
    tcp_count INTEGER,
    udp_count INTEGER,
    icmp_count INTEGER,
    arp_count INTEGER,
    dropped_packets INTEGER,
    parsing_errors INTEGER
);

CREATE TABLE IF NOT EXISTS nids_detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_key TEXT,
    timestamp TEXT,
    prediction TEXT,
    confidence REAL,
    model_version TEXT
);

CREATE TABLE IF NOT EXISTS model_predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    prediction_id TEXT UNIQUE,
    flow_key TEXT,
    model_name TEXT,
    model_version TEXT,
    confidence REAL,
    prediction TEXT,
    inference_time_ms REAL,
    timestamp TEXT
);

CREATE INDEX IF NOT EXISTS idx_predictions_flow ON model_predictions(flow_key);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT UNIQUE,
    timestamp TEXT,
    severity TEXT,
    confidence REAL,
    source_ip TEXT,
    dest_ip TEXT,
    protocol TEXT,
    attack_type TEXT,
    status TEXT DEFAULT 'OPEN'
);

CREATE TABLE IF NOT EXISTS threat_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT,
    timestamp TEXT,
    mitre_technique TEXT,
    kill_chain_stage TEXT,
    cvss_score REAL,
    iocs TEXT,
    recommendation TEXT
);
"""


# =========================================================
# SCHEMA_STEP3 — Network Intelligence Layer tables
# =========================================================
SCHEMA_STEP3 = """
CREATE TABLE IF NOT EXISTS device_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_device TEXT,
    dst_device TEXT,
    first_seen TEXT,
    last_seen TEXT,
    communications INTEGER DEFAULT 0,
    bytes_total INTEGER DEFAULT 0,
    UNIQUE(src_device, dst_device)
);

CREATE INDEX IF NOT EXISTS idx_conn_src ON device_connections(src_device);
CREATE INDEX IF NOT EXISTS idx_conn_dst ON device_connections(dst_device);

CREATE TABLE IF NOT EXISTS protocol_statistics (
    protocol TEXT PRIMARY KEY,
    packets INTEGER DEFAULT 0,
    bytes_total INTEGER DEFAULT 0,
    last_updated TEXT
);

CREATE TABLE IF NOT EXISTS network_statistics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    timestamp TEXT,
    total_packets INTEGER,
    total_bytes INTEGER,
    active_devices INTEGER,
    active_flows INTEGER,
    pps REAL,
    bps REAL,
    avg_packet_size REAL,
    avg_flow_duration REAL,
    tcp_connections INTEGER,
    udp_connections INTEGER,
    dns_requests INTEGER,
    arp_requests INTEGER,
    capture_duration REAL
);
"""


# =========================================================
# SCHEMA_STEP4 — Feature Extraction & ML Detection tables
# =========================================================
SCHEMA_STEP4 = """
CREATE TABLE IF NOT EXISTS feature_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id TEXT,
    flow_key TEXT,
    feature_vector TEXT,
    feature_vector_hash TEXT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_snapshot_flow ON feature_snapshots(flow_id);

CREATE TABLE IF NOT EXISTS dead_letter_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    queue_name TEXT,
    payload TEXT,
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP
);
"""

# =========================================================
# SCHEMA_STEP5 — Alert, Incident & Fusion Layer
# =========================================================
SCHEMA_STEP5 = """
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    title TEXT,
    status TEXT DEFAULT 'NEW',
    severity TEXT,
    risk_level TEXT,
    attack_type TEXT,
    source_ip TEXT,
    dest_ip TEXT,
    alert_count INTEGER DEFAULT 1,
    created_at TEXT,
    updated_at TEXT,
    closed_at TEXT,
    analyst TEXT,
    fusion_type TEXT DEFAULT 'NIDS_ONLY'
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_src ON incidents(source_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_updated ON incidents(updated_at);

CREATE TABLE IF NOT EXISTS incident_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT,
    event TEXT,
    old_status TEXT,
    new_status TEXT,
    actor TEXT,
    timestamp TEXT
);

CREATE INDEX IF NOT EXISTS idx_history_incident ON incident_history(incident_id);

CREATE TABLE IF NOT EXISTS incident_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT,
    note TEXT,
    analyst TEXT,
    timestamp TEXT
);

CREATE INDEX IF NOT EXISTS idx_notes_incident ON incident_notes(incident_id);

CREATE TABLE IF NOT EXISTS incident_relations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT,
    alert_id TEXT,
    linked_at TEXT,
    UNIQUE(incident_id, alert_id)
);

CREATE INDEX IF NOT EXISTS idx_relations_incident ON incident_relations(incident_id);
CREATE INDEX IF NOT EXISTS idx_relations_alert ON incident_relations(alert_id);
"""


def _migrate_alerts_table(conn):
    """Extends the Step-2 `alerts` table with fields Step 5 needs."""
    existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    new_columns = {
        "prediction_id": "TEXT",
        "flow_id": "TEXT",
        "flow_key": "TEXT",
        "risk_level": "TEXT",
        "source": "TEXT DEFAULT 'NIDS'",     # NIDS or HIDS — used by Fusion Engine
        "incident_id": "TEXT",
        "correlation_key": "TEXT",
    }
    for col, col_type in new_columns.items():
        if col not in existing_cols:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} {col_type}")
            logger.info(f"Migrated alerts table: added column '{col}'")


# Add to init_db(): conn.executescript(SCHEMA_STEP5), _migrate_alerts_table(conn)


# =========================================================
# Migrations — additive, idempotent (safe to run every startup)
# =========================================================
def _migrate_devices_table(conn):
    existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(devices)").fetchall()}
    new_columns = {
        "device_id": "TEXT",
        "interface": "TEXT",
        "incoming_packets": "INTEGER DEFAULT 0",
        "outgoing_packets": "INTEGER DEFAULT 0",
        "active_flows": "INTEGER DEFAULT 0",
        "trust_score": "TEXT DEFAULT 'Unknown'",
    }
    for col, col_type in new_columns.items():
        if col not in existing_cols:
            conn.execute(f"ALTER TABLE devices ADD COLUMN {col} {col_type}")
            logger.info(f"Migrated devices table: added column '{col}'")


def _migrate_flows_table(conn):
    existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(flows)").fetchall()}
    new_columns = {
        "flow_id": "TEXT",
        "active_time": "REAL DEFAULT 0",
        "idle_time": "REAL DEFAULT 0",
    }
    for col, col_type in new_columns.items():
        if col not in existing_cols:
            conn.execute(f"ALTER TABLE flows ADD COLUMN {col} {col_type}")
            logger.info(f"Migrated flows table: added column '{col}'")


def _migrate_predictions_table(conn):
    existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(model_predictions)").fetchall()}
    new_columns = {
        "flow_id": "TEXT",
        "attack_type": "TEXT",
        "probability": "REAL",
        "severity": "TEXT",
        "feature_version": "TEXT",
        "feature_vector_hash": "TEXT",
    }
    for col, col_type in new_columns.items():
        if col not in existing_cols:
            conn.execute(f"ALTER TABLE model_predictions ADD COLUMN {col} {col_type}")
            logger.info(f"Migrated model_predictions table: added column '{col}'")


# =========================================================
# init_db — the ONE definition, runs everything
# =========================================================
def init_db():
    conn = get_connection()
    with _write_lock:
        conn.executescript(SCHEMA)
        conn.executescript(SCHEMA_STEP3)
        conn.executescript(SCHEMA_STEP4)
        conn.executescript(SCHEMA_STEP5)

        _migrate_devices_table(conn)
        _migrate_flows_table(conn)
        _migrate_predictions_table(conn)
        _migrate_alerts_table(conn)

        conn.commit()
    logger.info("Database schema initialized (Steps 1-5 tables + migrations complete)")


# =========================================================
# Packets
# =========================================================
def insert_packets_batch(packets: list):
    if not packets:
        return
    conn = get_connection()
    rows = [
        (
            p.get("session_id"), p["timestamp"], p["interface"],
            p.get("eth_src"), p.get("eth_dst"), p.get("ip_version"),
            p.get("src_ip"), p.get("dst_ip"), p.get("src_port"), p.get("dst_port"),
            p.get("protocol"), p.get("length"), p.get("ttl"), p.get("flags"),
            p.get("dns_query"), p.get("http_host"),
            int(p.get("is_fragmented", False)), int(p.get("parse_error", False)),
        )
        for p in packets
    ]
    try:
        with _write_lock:
            conn.executemany("""
                INSERT INTO packets
                (session_id, timestamp, interface, eth_src, eth_dst, ip_version,
                 src_ip, dst_ip, src_port, dst_port, protocol, length, ttl, flags,
                 dns_query, http_host, is_fragmented, parse_error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Packet batch insert failed: {e}")
        raise


def fetch_recent_packets(limit: int = 50):
    conn = get_connection()
    cursor = conn.execute("""
        SELECT timestamp, interface, src_ip, dst_ip, src_port, dst_port,
               protocol, length, ttl, flags, dns_query, http_host
        FROM packets ORDER BY id DESC LIMIT ?
    """, (limit,))
    cols = [c[0] for c in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


def count_packets():
    conn = get_connection()
    return conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]


# =========================================================
# Devices
# =========================================================
def upsert_device(device: dict):
    conn = get_connection()
    with _write_lock:
        conn.execute("""
            INSERT INTO devices (ip, mac, hostname, vendor, device_id, interface, first_seen, last_seen,
                                  packet_count, bytes_total, incoming_packets, outgoing_packets,
                                  active_flows, status, trust_score)
            VALUES (:ip, :mac, :hostname, :vendor, :device_id, :interface, :first_seen, :last_seen,
                    :packet_count, :bytes_total, :incoming_packets, :outgoing_packets,
                    :active_flows, :status, :trust_score)
            ON CONFLICT(ip) DO UPDATE SET
                mac = excluded.mac,
                hostname = CASE WHEN excluded.hostname != 'Unknown' THEN excluded.hostname ELSE devices.hostname END,
                vendor = CASE WHEN excluded.vendor != 'Unknown' THEN excluded.vendor ELSE devices.vendor END,
                interface = excluded.interface,
                last_seen = excluded.last_seen,
                packet_count = devices.packet_count + excluded.packet_count,
                bytes_total = devices.bytes_total + excluded.bytes_total,
                incoming_packets = devices.incoming_packets + excluded.incoming_packets,
                outgoing_packets = devices.outgoing_packets + excluded.outgoing_packets,
                active_flows = excluded.active_flows,
                status = excluded.status
        """, device)
        conn.commit()


def fetch_devices():
    conn = get_connection()
    cursor = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC")
    cols = [c[0] for c in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


def mark_devices_offline(threshold_seconds: int = 120):
    """Devices with no traffic for `threshold_seconds` are marked Offline (Module 12: device timeout)."""
    conn = get_connection()
    with _write_lock:
        conn.execute("""
            UPDATE devices SET status = 'Offline'
            WHERE status = 'Online'
              AND (strftime('%s','now') - strftime('%s', last_seen)) > ?
        """, (threshold_seconds,))
        conn.commit()


# =========================================================
# Device connections
# =========================================================
def upsert_device_connection(conn_data: dict):
    conn = get_connection()
    with _write_lock:
        conn.execute("""
            INSERT INTO device_connections (src_device, dst_device, first_seen, last_seen, communications, bytes_total)
            VALUES (:src_device, :dst_device, :first_seen, :last_seen, :communications, :bytes_total)
            ON CONFLICT(src_device, dst_device) DO UPDATE SET
                last_seen = excluded.last_seen,
                communications = device_connections.communications + excluded.communications,
                bytes_total = device_connections.bytes_total + excluded.bytes_total
        """, conn_data)
        conn.commit()


def fetch_device_connections(limit: int = 500):
    conn = get_connection()
    cursor = conn.execute("SELECT * FROM device_connections ORDER BY last_seen DESC LIMIT ?", (limit,))
    cols = [c[0] for c in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


# =========================================================
# Flows
# =========================================================
def upsert_flow(flow: dict):
    conn = get_connection()
    with _write_lock:
        conn.execute("""
            INSERT INTO flows (flow_key, src_ip, dst_ip, src_port, dst_port, protocol,
                                first_seen, last_seen, packet_count, byte_count,
                                fwd_packets, bwd_packets, status,
                                flow_id, active_time, idle_time)
            VALUES (:flow_key, :src_ip, :dst_ip, :src_port, :dst_port, :protocol,
                    :first_seen, :last_seen, :packet_count, :byte_count,
                    :fwd_packets, :bwd_packets, :status,
                    :flow_id, :active_time, :idle_time)
            ON CONFLICT(flow_key) DO UPDATE SET
                last_seen = excluded.last_seen,
                packet_count = flows.packet_count + excluded.packet_count,
                byte_count = flows.byte_count + excluded.byte_count,
                fwd_packets = flows.fwd_packets + excluded.fwd_packets,
                bwd_packets = flows.bwd_packets + excluded.bwd_packets,
                status = excluded.status,
                flow_id = excluded.flow_id,
                active_time = excluded.active_time,
                idle_time = excluded.idle_time
        """, {
            **flow,
            "flow_id": flow.get("flow_id"),
            "active_time": flow.get("active_time", 0.0),
            "idle_time": flow.get("idle_time", 0.0),
        })
        conn.commit()


def fetch_flows(limit: int = 100):
    conn = get_connection()
    cursor = conn.execute("SELECT * FROM flows ORDER BY last_seen DESC LIMIT ?", (limit,))
    cols = [c[0] for c in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


# =========================================================
# Capture sessions
# =========================================================
def create_session(session: dict):
    conn = get_connection()
    with _write_lock:
        conn.execute("""
            INSERT INTO capture_sessions (session_id, interface, start_time, status)
            VALUES (:session_id, :interface, :start_time, :status)
        """, session)
        conn.commit()


def finalize_session(session_id: str, stats: dict):
    conn = get_connection()
    with _write_lock:
        conn.execute("""
            UPDATE capture_sessions
            SET stop_time = :stop_time, duration_seconds = :duration_seconds,
                total_packets = :total_packets, total_bytes = :total_bytes,
                avg_pps = :avg_pps, avg_bps = :avg_bps, status = :status
            WHERE session_id = :session_id
        """, {**stats, "session_id": session_id})
        conn.commit()


def fetch_sessions(limit: int = 20):
    conn = get_connection()
    cursor = conn.execute("SELECT * FROM capture_sessions ORDER BY start_time DESC LIMIT ?", (limit,))
    cols = [c[0] for c in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


# =========================================================
# Statistics snapshots (Step 2 — low-level capture stats)
# =========================================================
def insert_statistics_snapshot(snapshot: dict):
    conn = get_connection()
    with _write_lock:
        conn.execute("""
            INSERT INTO capture_statistics
            (session_id, timestamp, total_packets, packets_per_sec, bytes_per_sec,
             total_bytes, active_flows, active_devices, tcp_count, udp_count,
             icmp_count, arp_count, dropped_packets, parsing_errors)
            VALUES (:session_id, :timestamp, :total_packets, :packets_per_sec, :bytes_per_sec,
                    :total_bytes, :active_flows, :active_devices, :tcp_count, :udp_count,
                    :icmp_count, :arp_count, :dropped_packets, :parsing_errors)
        """, snapshot)
        conn.commit()


# =========================================================
# Protocol statistics (Step 3)
# =========================================================
def upsert_protocol_stat(protocol: str, packets: int, bytes_total: int, timestamp: str):
    conn = get_connection()
    with _write_lock:
        conn.execute("""
            INSERT INTO protocol_statistics (protocol, packets, bytes_total, last_updated)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(protocol) DO UPDATE SET
                packets = protocol_statistics.packets + excluded.packets,
                bytes_total = protocol_statistics.bytes_total + excluded.bytes_total,
                last_updated = excluded.last_updated
        """, (protocol, packets, bytes_total, timestamp))
        conn.commit()


def fetch_protocol_statistics():
    conn = get_connection()
    cursor = conn.execute("SELECT * FROM protocol_statistics ORDER BY packets DESC")
    cols = [c[0] for c in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


# =========================================================
# Network statistics snapshots (Step 3 — high-level intelligence stats)
# =========================================================
def insert_network_statistics(snapshot: dict):
    conn = get_connection()
    with _write_lock:
        conn.execute("""
            INSERT INTO network_statistics
            (session_id, timestamp, total_packets, total_bytes, active_devices, active_flows,
             pps, bps, avg_packet_size, avg_flow_duration, tcp_connections, udp_connections,
             dns_requests, arp_requests, capture_duration)
            VALUES (:session_id, :timestamp, :total_packets, :total_bytes, :active_devices, :active_flows,
                    :pps, :bps, :avg_packet_size, :avg_flow_duration, :tcp_connections, :udp_connections,
                    :dns_requests, :arp_requests, :capture_duration)
        """, snapshot)
        conn.commit()


def fetch_latest_network_statistics():
    conn = get_connection()
    cols_info = conn.execute("PRAGMA table_info(network_statistics)").fetchall()
    col_names = [c[1] for c in cols_info]

    row = conn.execute("SELECT * FROM network_statistics ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        return None
    return dict(zip(col_names, row))


# =========================================================
# Model predictions (Step 4)
# =========================================================
def insert_prediction(prediction: dict):
    conn = get_connection()
    with _write_lock:
        conn.execute("""
            INSERT INTO model_predictions
            (prediction_id, flow_id, flow_key, model_name, model_version, confidence,
             prediction, attack_type, probability, severity, feature_version,
             feature_vector_hash, inference_time_ms, timestamp)
            VALUES (:prediction_id, :flow_id, :flow_key, :model_name, :model_version, :confidence,
                    :prediction, :attack_type, :probability, :severity, :feature_version,
                    :feature_vector_hash, :inference_time_ms, :timestamp)
        """, prediction)
        conn.commit()


def fetch_predictions(limit: int = 100):
    conn = get_connection()
    cursor = conn.execute("SELECT * FROM model_predictions ORDER BY id DESC LIMIT ?", (limit,))
    cols = [c[0] for c in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


def fetch_prediction_by_id(prediction_id: str):
    conn = get_connection()
    cols_info = conn.execute("PRAGMA table_info(model_predictions)").fetchall()
    col_names = [c[1] for c in cols_info]

    row = conn.execute(
        "SELECT * FROM model_predictions WHERE prediction_id = ?", (prediction_id,)
    ).fetchone()
    if not row:
        return None
    return dict(zip(col_names, row))


def fetch_prediction_summary():
    conn = get_connection()
    row = conn.execute("""
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN prediction = 'Attack' THEN 1 ELSE 0 END) as attacks,
            SUM(CASE WHEN prediction = 'Normal' THEN 1 ELSE 0 END) as normal,
            AVG(inference_time_ms) as avg_inference_ms
        FROM model_predictions
    """).fetchone()
    total, attacks, normal, avg_inference = row
    return {
        "total_predictions": total or 0,
        "attack_count": attacks or 0,
        "normal_count": normal or 0,
        "detection_rate": round((attacks or 0) / total, 4) if total else 0.0,
        "avg_inference_time_ms": round(avg_inference, 4) if avg_inference else 0.0,
    }


def fetch_attack_type_breakdown():
    conn = get_connection()
    cursor = conn.execute("""
        SELECT attack_type, COUNT(*) as count
        FROM model_predictions
        WHERE prediction = 'Attack'
        GROUP BY attack_type
        ORDER BY count DESC
    """)
    return [{"attack_type": row[0], "count": row[1]} for row in cursor.fetchall()]


# =========================================================
# Feature snapshots (Step 4)
# =========================================================
def insert_feature_snapshot(snapshot_data: dict):
    conn = get_connection()
    with _write_lock:
        conn.execute("""
            INSERT INTO feature_snapshots (flow_id, flow_key, feature_vector, feature_vector_hash)
            VALUES (:flow_id, :flow_key, :feature_vector, :feature_vector_hash)
        """, snapshot_data)
        conn.commit()


def fetch_feature_snapshot(flow_id: str):
    conn = get_connection()
    cols_info = conn.execute("PRAGMA table_info(feature_snapshots)").fetchall()
    col_names = [c[1] for c in cols_info]

    row = conn.execute(
        "SELECT * FROM feature_snapshots WHERE flow_id = ? ORDER BY id DESC LIMIT 1", (flow_id,)
    ).fetchone()
    if not row:
        return None
    return dict(zip(col_names, row))


# =========================================================
# Dead letter queue (Step 4)
# =========================================================
def insert_dead_letter(queue_name: str, payload: str, error_message: str, retry_count: int = 0):
    conn = get_connection()
    with _write_lock:
        conn.execute("""
            INSERT INTO dead_letter_queue (queue_name, payload, error_message, retry_count)
            VALUES (?, ?, ?, ?)
        """, (queue_name, payload, error_message, retry_count))
        conn.commit()
    logger.warning(f"Item sent to dead letter queue [{queue_name}]: {error_message}")


def fetch_dead_letters(limit: int = 100):
    conn = get_connection()
    cursor = conn.execute("SELECT * FROM dead_letter_queue ORDER BY id DESC LIMIT ?", (limit,))
    cols = [c[0] for c in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]

# =========================================================
# Alerts (Step 5)
# =========================================================
def insert_alert(alert: dict):
    conn = get_connection()
    with _write_lock:
        conn.execute("""
            INSERT INTO alerts
            (alert_id, timestamp, severity, confidence, source_ip, dest_ip, protocol,
             attack_type, status, prediction_id, flow_id, flow_key, risk_level,
             source, incident_id, correlation_key)
            VALUES (:alert_id, :timestamp, :severity, :confidence, :source_ip, :dest_ip, :protocol,
                    :attack_type, :status, :prediction_id, :flow_id, :flow_key, :risk_level,
                    :source, :incident_id, :correlation_key)
        """, alert)
        conn.commit()


def update_alert_incident(alert_id: str, incident_id: str):
    conn = get_connection()
    with _write_lock:
        conn.execute(
            "UPDATE alerts SET incident_id = ? WHERE alert_id = ?", (incident_id, alert_id)
        )
        conn.commit()


def fetch_alerts(limit: int = 100, status: str = None):
    conn = get_connection()
    if status:
        cursor = conn.execute(
            "SELECT * FROM alerts WHERE status = ? ORDER BY id DESC LIMIT ?", (status, limit)
        )
    else:
        cursor = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    cols = [c[0] for c in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


def fetch_alert_by_id(alert_id: str):
    conn = get_connection()
    cols_info = conn.execute("PRAGMA table_info(alerts)").fetchall()
    col_names = [c[1] for c in cols_info]
    row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    if not row:
        return None
    return dict(zip(col_names, row))


def fetch_recent_alerts_for_correlation(correlation_key: str, window_seconds: int):
    """Finds recent OPEN alerts sharing a correlation_key within the time window (Module 2/6)."""
    conn = get_connection()
    cursor = conn.execute("""
        SELECT * FROM alerts
        WHERE correlation_key = ?
          AND (strftime('%s','now') - strftime('%s', timestamp)) <= ?
        ORDER BY id DESC
    """, (correlation_key, window_seconds))
    cols = [c[0] for c in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


def fetch_alert_severity_distribution():
    conn = get_connection()
    cursor = conn.execute("""
        SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity ORDER BY count DESC
    """)
    return [{"severity": row[0], "count": row[1]} for row in cursor.fetchall()]


# =========================================================
# Incidents (Step 5)
# =========================================================
def create_incident(incident: dict):
    conn = get_connection()
    with _write_lock:
        conn.execute("""
            INSERT INTO incidents
            (incident_id, title, status, severity, risk_level, attack_type,
             source_ip, dest_ip, alert_count, created_at, updated_at, analyst, fusion_type)
            VALUES (:incident_id, :title, :status, :severity, :risk_level, :attack_type,
                    :source_ip, :dest_ip, :alert_count, :created_at, :updated_at, :analyst, :fusion_type)
        """, incident)
        conn.commit()


def update_incident(incident_id: str, updates: dict):
    if not updates:
        return
    set_clause = ", ".join(f"{k} = :{k}" for k in updates)
    conn = get_connection()
    with _write_lock:
        conn.execute(
            f"UPDATE incidents SET {set_clause} WHERE incident_id = :incident_id",
            {**updates, "incident_id": incident_id}
        )
        conn.commit()


def fetch_incident_by_id(incident_id: str):
    conn = get_connection()
    cols_info = conn.execute("PRAGMA table_info(incidents)").fetchall()
    col_names = [c[1] for c in cols_info]
    row = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
    if not row:
        return None
    return dict(zip(col_names, row))


def fetch_incidents(limit: int = 100, status: str = None):
    conn = get_connection()
    if status:
        cursor = conn.execute(
            "SELECT * FROM incidents WHERE status = ? ORDER BY updated_at DESC LIMIT ?", (status, limit)
        )
    else:
        cursor = conn.execute("SELECT * FROM incidents ORDER BY updated_at DESC LIMIT ?", (limit,))
    cols = [c[0] for c in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


def fetch_open_incident_by_correlation(correlation_key: str, window_seconds: int):
    """Finds an existing open incident matching this correlation key, within the time window."""
    conn = get_connection()
    row = conn.execute("""
        SELECT i.* FROM incidents i
        JOIN alerts a ON a.incident_id = i.incident_id
        WHERE a.correlation_key = ?
          AND i.status NOT IN ('RESOLVED', 'CLOSED')
          AND (strftime('%s','now') - strftime('%s', i.updated_at)) <= ?
        ORDER BY i.updated_at DESC
        LIMIT 1
    """, (correlation_key, window_seconds)).fetchone()
    if not row:
        return None
    cols_info = conn.execute("PRAGMA table_info(incidents)").fetchall()
    col_names = [c[1] for c in cols_info]
    return dict(zip(col_names, row))


# =========================================================
# Incident history / notes / relations
# =========================================================
def insert_incident_history(entry: dict):
    conn = get_connection()
    with _write_lock:
        conn.execute("""
            INSERT INTO incident_history (incident_id, event, old_status, new_status, actor, timestamp)
            VALUES (:incident_id, :event, :old_status, :new_status, :actor, :timestamp)
        """, entry)
        conn.commit()


def fetch_incident_history(incident_id: str):
    conn = get_connection()
    cursor = conn.execute(
        "SELECT * FROM incident_history WHERE incident_id = ? ORDER BY id ASC", (incident_id,)
    )
    cols = [c[0] for c in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


def insert_incident_note(note: dict):
    conn = get_connection()
    with _write_lock:
        conn.execute("""
            INSERT INTO incident_notes (incident_id, note, analyst, timestamp)
            VALUES (:incident_id, :note, :analyst, :timestamp)
        """, note)
        conn.commit()


def fetch_incident_notes(incident_id: str):
    conn = get_connection()
    cursor = conn.execute(
        "SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY id ASC", (incident_id,)
    )
    cols = [c[0] for c in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


def link_alert_to_incident(incident_id: str, alert_id: str):
    conn = get_connection()
    with _write_lock:
        conn.execute("""
            INSERT OR IGNORE INTO incident_relations (incident_id, alert_id, linked_at)
            VALUES (?, ?, datetime('now'))
        """, (incident_id, alert_id))
        conn.commit()


def fetch_incident_alerts(incident_id: str):
    conn = get_connection()
    cursor = conn.execute("SELECT * FROM alerts WHERE incident_id = ? ORDER BY timestamp ASC", (incident_id,))
    cols = [c[0] for c in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


# =========================================================
# Initialize on import
# =========================================================
init_db()