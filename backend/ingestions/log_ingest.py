"""
Real-time Log Ingestion with System Log Monitoring
"""

import os
import re
import threading
from datetime import datetime
from typing import List, Dict, Callable, Optional
from pathlib import Path

from backend.parsing.ssh_parser import SSHLogParser


class SystemLogMonitor:
    """Real-time monitoring of system authentication logs"""
    
    def __init__(self, log_path: str = "/var/log/auth.log"):
        self.log_path = log_path
        self.parser = SSHLogParser()
        self.last_position = 0
        self.is_monitoring = False
        self.monitor_thread = None
        self.callbacks: List[Callable] = []
        
        self._initialize_position()
    
    def _initialize_position(self):
        """Set initial position to end of file"""
        try:
            if os.path.exists(self.log_path):
                self.last_position = os.path.getsize(self.log_path)
        except:
            self.last_position = 0
    
    def add_callback(self, callback: Callable):
        """Add callback to be called on new log events"""
        self.callbacks.append(callback)
    
    def start_monitoring(self):
        """Start monitoring log file for changes"""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        print(f"[HIDS] Started monitoring {self.log_path}")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
    
    def _monitor_loop(self):
        """Background thread for monitoring"""
        while self.is_monitoring:
            try:
                if os.path.exists(self.log_path):
                    current_size = os.path.getsize(self.log_path)
                    
                    if current_size > self.last_position:
                        self._read_new_lines()
                    elif current_size < self.last_position:
                        # File was rotated
                        self.last_position = 0
                
                threading.Event().wait(1.0)  # Check every second
            
            except Exception as e:
                print(f"[HIDS] Monitor error: {e}")
    
    def _read_new_lines(self):
        """Read new lines from log file"""
        try:
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()
                
                for line in new_lines:
                    event = self.parser.parse_line(line)
                    if event:
                        # Trigger callbacks
                        for callback in self.callbacks:
                            try:
                                callback(event)
                            except:
                                pass
        
        except Exception as e:
            print(f"[HIDS] Read error: {e}")


class LogIngestor:
    """Log ingestion with both real-time and manual modes"""
    
    def __init__(self, enable_monitoring: bool = True):
        self.parsers = {
            "ssh": SSHLogParser()
        }
        self.monitor = None
        self.monitored_events = []
        
        if enable_monitoring:
            self.monitor = SystemLogMonitor()
            self.monitor.add_callback(self._on_new_event)
            self.monitor.start_monitoring()
    
    def _on_new_event(self, event: Dict):
        """Callback for new monitored events"""
        self.monitored_events.append(event)
    
    def ingest_file(self, filepath: str, source: str = "ssh") -> List[Dict]:
        """Manual ingestion of log file"""
        
        parser = self.parsers.get(source)
        if not parser:
            raise ValueError(f"No parser for source: {source}")
        
        events = []
        
        try:
            with open(filepath, "r", encoding='utf-8', errors='ignore') as f:
                for line in f:
                    event = parser.parse_line(line)
                    if event:
                        events.append(event)
        
        except FileNotFoundError:
            print(f"[HIDS] File not found: {filepath}")
            return []
        
        return events
    
    def get_monitored_events(self, since_timestamp: Optional[str] = None) -> List[Dict]:
        """Get events from real-time monitoring"""
        
        if since_timestamp:
            return [
                e for e in self.monitored_events
                if e.get("timestamp", "") >= since_timestamp
            ]
        
        return self.monitored_events[-100:]  # Last 100 events
    
    def clear_monitored_events(self):
        """Clear event buffer"""
        self.monitored_events.clear()
    
    def shutdown(self):
        """Shutdown monitoring"""
        if self.monitor:
            self.monitor.stop_monitoring()