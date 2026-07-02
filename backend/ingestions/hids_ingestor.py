"""
Unified HIDS Ingestor
Supports both live monitoring and manual log analysis
"""

import threading
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path

from backend.ingestions.log_monitor import SystemLogMonitor
from backend.parsing.log_parser import AuthenticationLogParser
from backend.features.event_builder import EventBuilder
from backend.detection.hids_engine import HIDSDetectionEngine
from backend.storage.nids_store import nids_db


class HIDSIngestor:
    """Unified HIDS with live monitoring and manual analysis modes"""
    
    MODE_LIVE = "live"
    MODE_MANUAL = "manual"
    
    def __init__(self):
        self.mode = self.MODE_LIVE
        self.is_running = False
        
        # Components
        self.log_monitor = SystemLogMonitor()
        self.parser = AuthenticationLogParser()
        self.event_builder = EventBuilder()
        self.detection_engine = HIDSDetectionEngine()
        
        # Statistics
        self.stats = {
            "events_parsed": 0,
            "sessions_created": 0,
            "detections": 0,
            "alerts": 0
        }
        
        # Setup callbacks
        if self.log_monitor.log_file:
            self.log_monitor.add_callback(self._on_new_log_line)
    
    def start_live_monitoring(self) -> bool:
        """Start real-time log monitoring"""
        
        if self.is_running:
            return True
        
        if not self.log_monitor.log_file:
            print("[HIDS] ERROR: No log file detected for live monitoring")
            return False
        
        self.mode = self.MODE_LIVE
        self.is_running = True
        
        success = self.log_monitor.start_monitoring()
        if success:
            print("[HIDS] Live monitoring started")
        
        return success
    
    def stop_live_monitoring(self):
        """Stop live monitoring"""
        
        self.is_running = False
        self.log_monitor.stop_monitoring()
        
        # Process any remaining sessions
        self._process_completed_sessions()
        
        print("[HIDS] Live monitoring stopped")
    
    def analyze_manual_log(self, file_path: str) -> List[Dict]:
        """
        Analyze log file manually
        Returns: List of detection results
        """
        
        self.mode = self.MODE_MANUAL
        self.is_running = True
        detections = []
        
        try:
            if not Path(file_path).exists():
                print(f"[HIDS] File not found: {file_path}")
                return []
            
            print(f"[HIDS] Analyzing {file_path}")
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if line.strip():
                        event = self.parser.parse_line(line)
                        if event:
                            self.stats["events_parsed"] += 1
                            
                            # Add to session
                            session_id, session = self.event_builder.add_event(event)
            
            # Process all sessions
            self.event_builder.session_timeout = 0  # Force completion
            completed = self.event_builder.get_completed_sessions()
            
            for session in completed:
                detection = self.detection_engine.predict_session(session.to_dict())
                detections.append(detection)
                self.stats["detections"] += 1
                
                # Store result
                nids_db.insert_alert({
                    "flow_id": session.session_id,
                    "timestamp": datetime.now().isoformat(),
                    "attack_type": detection.get("attack_type"),
                    "severity": detection.get("severity"),
                    "confidence": detection.get("confidence"),
                    "decision": detection.get("prediction"),
                    "source_ip": session.source_ip,
                    "alert_data_json": str(detection)
                })
                self.stats["alerts"] += 1
        
        except Exception as e:
            print(f"[HIDS] Error analyzing log: {e}")
        
        finally:
            self.is_running = False
        
        return detections
    
    def _on_new_log_line(self, line: str):
        """Callback for new log line from monitor"""
        
        try:
            # Parse line
            event = self.parser.parse_line(line)
            if not event:
                return
            
            self.stats["events_parsed"] += 1
            
            # Add to session
            session_id, session = self.event_builder.add_event(event)
            
            # Check for completed sessions
            self._process_completed_sessions()
        
        except Exception as e:
            print(f"[HIDS] Error processing line: {e}")
    
    def _process_completed_sessions(self):
        """Process completed sessions and generate detections"""
        
        completed = self.event_builder.get_completed_sessions()
        
        for session in completed:
            try:
                self.stats["sessions_created"] += 1
                
                # Perform detection
                detection = self.detection_engine.predict_session(session.to_dict())
                self.stats["detections"] += 1
                
                # Store in database
                nids_db.insert_alert({
                    "flow_id": session.session_id,
                    "timestamp": datetime.now().isoformat(),
                    "attack_type": detection.get("attack_type"),
                    "severity": detection.get("severity"),
                    "confidence": detection.get("confidence"),
                    "decision": detection.get("prediction"),
                    "source_ip": session.source_ip,
                    "alert_data_json": str(detection)
                })
                self.stats["alerts"] += 1
                
                # Print if attack detected
                if detection.get("prediction") == "Attack":
                    print(f"[HIDS] ALERT: {detection['attack_type']} from {session.source_ip}")
            
            except Exception as e:
                print(f"[HIDS] Detection error: {e}")
    
    def get_status(self) -> Dict:
        """Get HIDS status"""
        
        return {
            "mode": self.mode,
            "is_running": self.is_running,
            "log_monitor": self.log_monitor.get_status(),
            "event_builder": self.event_builder.get_stats(),
            "stats": self.stats
        }
    
    def get_active_sessions(self) -> Dict:
        """Get active authentication sessions"""
        return self.event_builder.get_active_sessions()
    
    def get_recent_detections(self, limit: int = 50) -> List[Dict]:
        """Get recent detection results"""
        return nids_db.get_recent_detections(limit)


# Global instance
hids_ingestor = HIDSIngestor()