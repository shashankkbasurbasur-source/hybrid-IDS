"""
Persistent Storage for NIDS (SQLite)
Stores packets, flows, and detections
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
import threading


class NIDSDatabase:
    """SQLite database for NIDS data persistence"""
    
    def __init__(self, db_path: str = "nids_data.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._initialize_db()
    
    def _initialize_db(self):
        """Create tables if they don't exist"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Packets table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT NOT NULL,
                    length INTEGER,
                    ttl INTEGER,
                    flags TEXT,
                    flow_id TEXT,
                    raw_data TEXT
                )
            """)
            
            # Flows table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS flows (
                    flow_id TEXT PRIMARY KEY,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    packet_count INTEGER DEFAULT 0,
                    byte_count INTEGER DEFAULT 0,
                    duration REAL,
                    status TEXT DEFAULT 'active',
                    direction TEXT
                )
            """)
            
            # Features table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS features (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    features_json TEXT NOT NULL,
                    FOREIGN KEY (flow_id) REFERENCES flows(flow_id)
                )
            """)
            
            # Detections table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    prediction TEXT NOT NULL,
                    probability REAL NOT NULL,
                    attack_type TEXT,
                    confidence REAL,
                    binary_score REAL,
                    multiclass_scores_json TEXT,
                    FOREIGN KEY (flow_id) REFERENCES flows(flow_id)
                )
            """)
            
            # Alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id TEXT,
                    timestamp TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL,
                    nids_score REAL,
                    hids_score REAL,
                    final_score REAL,
                    decision TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    alert_data_json TEXT
                )
            """)
            
            # Statistics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS capture_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    packets_captured INTEGER,
                    bytes_captured INTEGER,
                    flows_active INTEGER,
                    flows_completed INTEGER,
                    packets_per_sec REAL,
                    bytes_per_sec REAL,
                    normal_flows INTEGER,
                    intrusion_flows INTEGER
                )
            """)
            
            conn.commit()
    
    def insert_packet(self, packet_data: Dict) -> int:
        """Insert captured packet"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO packets 
                    (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, 
                     length, ttl, flags, flow_id, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    packet_data.get("timestamp"),
                    packet_data.get("src_ip"),
                    packet_data.get("dst_ip"),
                    packet_data.get("src_port"),
                    packet_data.get("dst_port"),
                    packet_data.get("protocol"),
                    packet_data.get("length"),
                    packet_data.get("ttl"),
                    packet_data.get("flags"),
                    packet_data.get("flow_id"),
                    packet_data.get("raw_data")
                ))
                
                conn.commit()
                return cursor.lastrowid
    
    def insert_flow(self, flow_data: Dict) -> bool:
        """Insert or update flow"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT OR REPLACE INTO flows 
                    (flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
                     start_time, end_time, packet_count, byte_count, duration, status, direction)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    flow_data.get("flow_id"),
                    flow_data.get("src_ip"),
                    flow_data.get("dst_ip"),
                    flow_data.get("src_port"),
                    flow_data.get("dst_port"),
                    flow_data.get("protocol"),
                    flow_data.get("start_time"),
                    flow_data.get("end_time"),
                    flow_data.get("packet_count", 0),
                    flow_data.get("byte_count", 0),
                    flow_data.get("duration", 0),
                    flow_data.get("status", "active"),
                    flow_data.get("direction")
                ))
                
                conn.commit()
                return True
    
    def insert_detection(self, detection_data: Dict) -> int:
        """Insert detection result"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO detections 
                    (flow_id, timestamp, prediction, probability, attack_type, 
                     confidence, binary_score, multiclass_scores_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    detection_data.get("flow_id"),
                    detection_data.get("timestamp"),
                    detection_data.get("prediction"),
                    detection_data.get("probability"),
                    detection_data.get("attack_type"),
                    detection_data.get("confidence"),
                    detection_data.get("binary_score"),
                    json.dumps(detection_data.get("multiclass_scores", {}))
                ))
                
                conn.commit()
                return cursor.lastrowid
    
    def insert_alert(self, alert_data: Dict) -> int:
        """Insert alert"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO alerts 
                    (flow_id, timestamp, attack_type, severity, confidence,
                     nids_score, hids_score, final_score, decision, source_ip,
                     destination_ip, alert_data_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert_data.get("flow_id"),
                    alert_data.get("timestamp"),
                    alert_data.get("attack_type"),
                    alert_data.get("severity"),
                    alert_data.get("confidence"),
                    alert_data.get("nids_score"),
                    alert_data.get("hids_score"),
                    alert_data.get("final_score"),
                    alert_data.get("decision"),
                    alert_data.get("source_ip"),
                    alert_data.get("destination_ip"),
                    json.dumps(alert_data)
                ))
                
                conn.commit()
                return cursor.lastrowid
    
    def get_recent_packets(self, limit: int = 100) -> List[Dict]:
        """Get recent packets"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT * FROM packets 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """, (limit,))
                
                return [dict(row) for row in cursor.fetchall()]
    
    def get_active_flows(self) -> List[Dict]:
        """Get active flows"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT * FROM flows 
                    WHERE status = 'active'
                    ORDER BY start_time DESC
                """)
                
                return [dict(row) for row in cursor.fetchall()]
    
    def get_recent_detections(self, limit: int = 50) -> List[Dict]:
        """Get recent detections"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT d.*, f.src_ip, f.dst_ip, f.protocol
                    FROM detections d
                    JOIN flows f ON d.flow_id = f.flow_id
                    ORDER BY d.timestamp DESC
                    LIMIT ?
                """, (limit,))
                
                return [dict(row) for row in cursor.fetchall()]
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict]:
        """Get recent alerts"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT * FROM alerts 
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (limit,))
                
                results = cursor.fetchall()
                return [
                    {**dict(row), **json.loads(row['alert_data_json'])}
                    for row in results
                ]
    
    def get_capture_stats(self) -> Dict:
        """Get latest capture statistics"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("SELECT COUNT(*) FROM packets")
                total_packets = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM flows WHERE status='active'")
                active_flows = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM flows WHERE status='completed'")
                completed_flows = cursor.fetchone()[0]
                
                cursor.execute("""
                    SELECT COUNT(*) FROM detections 
                    WHERE prediction != 'normal'
                """)
                intrusions = cursor.fetchone()[0]
                
                cursor.execute("""
                    SELECT SUM(byte_count) FROM flows
                """)
                total_bytes = cursor.fetchone()[0] or 0
                
                return {
                    "total_packets": total_packets,
                    "active_flows": active_flows,
                    "completed_flows": completed_flows,
                    "intrusions_detected": intrusions,
                    "total_bytes": total_bytes
                }


# Global instance
nids_db = NIDSDatabase()