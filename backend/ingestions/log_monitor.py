"""
Real-Time Operating System Log Monitoring
Continuously monitors authentication logs for new entries
"""

import os
import threading
from datetime import datetime
from typing import List, Callable, Optional, Dict
from pathlib import Path
import platform


class SystemLogMonitor:
    """Real-time monitoring of system authentication logs"""
    
    # Log paths for different Linux distributions
    LOG_PATHS = {
        "ubuntu": "/var/log/auth.log",
        "debian": "/var/log/auth.log",
        "centos": "/var/log/secure",
        "rhel": "/var/log/secure",
        "fedora": "/var/log/secure",
        "arch": "/var/log/auth.log",
        "generic": ["/var/log/auth.log", "/var/log/secure", "/var/log/syslog"]
    }
    
    def __init__(self):
        self.is_monitoring = False
        self.monitor_thread = None
        self.log_file = None
        self.last_position = 0
        self.callbacks: List[Callable] = []
        self.stats = {
            "lines_read": 0,
            "errors": 0,
            "start_time": None
        }
        
        # Detect available log file
        self.log_file = self._detect_log_file()
    
    def _detect_log_file(self) -> Optional[str]:
        """Detect available system log file"""
        
        # Try common paths
        for path in self.LOG_PATHS["generic"]:
            if os.path.exists(path):
                try:
                    # Test read permission
                    with open(path, "r") as f:
                        pass
                    print(f"[HIDS] Detected log file: {path}")
                    return path
                except PermissionError:
                    print(f"[HIDS] Log file found but no permission: {path}")
                    return path
        
        return None
    
    def add_callback(self, callback: Callable):
        """Register callback for new log entries"""
        self.callbacks.append(callback)
    
    def start_monitoring(self):
        """Start real-time log monitoring"""
        
        if not self.log_file:
            print("[HIDS] ERROR: No authentication log file found")
            return False
        
        if self.is_monitoring:
            return True
        
        self.is_monitoring = True
        self.stats["start_time"] = datetime.now()
        self._initialize_position()
        
        # Start monitor thread
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True
        )
        self.monitor_thread.start()
        
        print(f"[HIDS] Started monitoring {self.log_file}")
        return True
    
    def stop_monitoring(self):
        """Stop log monitoring"""
        self.is_monitoring = False
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        print("[HIDS] Stopped monitoring")
    
    def _initialize_position(self):
        """Set initial position to end of file (only new entries)"""
        try:
            if os.path.exists(self.log_file):
                self.last_position = os.path.getsize(self.log_file)
        except:
            self.last_position = 0
    
    def _monitor_loop(self):
        """Background thread for log monitoring"""
        
        while self.is_monitoring:
            try:
                if not os.path.exists(self.log_file):
                    threading.Event().wait(1)
                    continue
                
                current_size = os.path.getsize(self.log_file)
                
                # File was truncated/rotated
                if current_size < self.last_position:
                    self.last_position = 0
                
                # New data available
                if current_size > self.last_position:
                    self._read_new_lines()
                
                threading.Event().wait(0.5)  # Check every 500ms
            
            except Exception as e:
                print(f"[HIDS] Monitor error: {e}")
                self.stats["errors"] += 1
                threading.Event().wait(1)
    
    def _read_new_lines(self):
        """Read and process new log lines"""
        
        try:
            with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()
                
                for line in new_lines:
                    if line.strip():
                        self.stats["lines_read"] += 1
                        
                        # Call callbacks
                        for callback in self.callbacks:
                            try:
                                callback(line.strip())
                            except Exception as e:
                                print(f"[HIDS] Callback error: {e}")
        
        except PermissionError:
            print(f"[HIDS] Permission denied reading {self.log_file}")
            self.stats["errors"] += 1
        except Exception as e:
            print(f"[HIDS] Read error: {e}")
            self.stats["errors"] += 1
    
    def get_status(self) -> Dict:
        """Get monitoring status"""
        return {
            "is_monitoring": self.is_monitoring,
            "log_file": self.log_file,
            "lines_read": self.stats["lines_read"],
            "errors": self.stats["errors"],
            "start_time": self.stats["start_time"].isoformat() if self.stats["start_time"] else None
        }