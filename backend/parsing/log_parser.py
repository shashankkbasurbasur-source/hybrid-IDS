"""
Comprehensive Log Parser for Authentication Logs
Supports multiple log formats
"""

import re
from datetime import datetime
from typing import Dict, Optional


class AuthenticationLogParser:
    """Parse authentication logs from multiple sources"""
    
    # SSH patterns
    SSH_PATTERNS = {
        "failed_password": re.compile(
            r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*"
            r"sshd\[.*?Failed password for (invalid user )?(?P<user>\w+) from (?P<ip>[\d.]+)"
        ),
        "accepted_password": re.compile(
            r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*"
            r"sshd\[.*?Accepted password for (?P<user>\w+) from (?P<ip>[\d.]+)"
        ),
        "accepted_pubkey": re.compile(
            r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*"
            r"sshd\[.*?Accepted publickey for (?P<user>\w+) from (?P<ip>[\d.]+)"
        ),
        "invalid_user": re.compile(
            r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*"
            r"sshd\[.*?Invalid user (?P<user>\w+) from (?P<ip>[\d.]+)"
        ),
        "connection_closed": re.compile(
            r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*"
            r"sshd\[.*?Connection closed by authenticating user (?P<user>\w+) (?P<ip>[\d.]+)"
        ),
        "authentication_failure": re.compile(
            r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*"
            r"Failed password for (?P<user>\w+)"
        ),
        "disconnected": re.compile(
            r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*"
            r"sshd\[.*?Disconnected from (?P<user>\w+) (?P<ip>[\d.]+)"
        )
    }
    
    # Sudo patterns
    SUDO_PATTERNS = {
        "sudo_success": re.compile(
            r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*"
            r"sudo:\s*(?P<user>\w+) : TTY=\S+ ; PWD=\S+ ; USER=\S+ ; COMMAND=(?P<command>.+)"
        ),
        "sudo_failure": re.compile(
            r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*"
            r"sudo:\s*(?P<user>\w+) : command not allowed"
        )
    }
    
    # Failed login patterns
    FAILED_LOGIN_PATTERNS = {
        "failed_login": re.compile(
            r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*"
            r"Failed (?P<type>password|publickey|keyboard-interactive) for "
            r"(invalid user )?(?P<user>[\w\-\.]+) from (?P<ip>[\d.]+)"
        ),
        "too_many_auth_failures": re.compile(
            r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*"
            r"Received disconnect from (?P<ip>[\d.]+) port \d+:11: Bye Bye \[preauth\]"
        )
    }
    
    MONTHS = {
        'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
        'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
    }
    
    def parse_line(self, line: str) -> Optional[Dict]:
        """Parse single log line"""
        
        if not line.strip():
            return None
        
        # Try SSH patterns
        for pattern_name, pattern in self.SSH_PATTERNS.items():
            match = pattern.search(line)
            if match:
                return self._build_event(
                    pattern_name, match.groupdict(), line
                )
        
        # Try SUDO patterns
        for pattern_name, pattern in self.SUDO_PATTERNS.items():
            match = pattern.search(line)
            if match:
                return self._build_event(
                    pattern_name, match.groupdict(), line
                )
        
        # Try failed login patterns
        for pattern_name, pattern in self.FAILED_LOGIN_PATTERNS.items():
            match = pattern.search(line)
            if match:
                return self._build_event(
                    pattern_name, match.groupdict(), line
                )
        
        return None
    
    def _build_event(self, event_type: str, groups: Dict, line: str) -> Dict:
        """Build structured event from regex groups"""
        
        # Determine event classification
        if "failed" in event_type.lower() or "failure" in event_type.lower():
            classification = "auth_fail"
        elif "accepted" in event_type.lower() or "success" in event_type.lower():
            classification = "auth_success"
        elif "sudo" in event_type.lower():
            classification = "privilege_escalation"
        elif "disconnected" in event_type.lower():
            classification = "disconnection"
        else:
            classification = "auth_event"
        
        # Parse timestamp
        month_str = groups.get("month", "Jan")
        day = int(groups.get("day", "1"))
        time_str = groups.get("time", "00:00:00")
        
        month_num = self.MONTHS.get(month_str, 1)
        
        timestamp = datetime.now().replace(
            month=month_num, day=day,
            hour=int(time_str.split(":")[0]),
            minute=int(time_str.split(":")[1]),
            second=int(time_str.split(":")[2])
        )
        
        return {
            "timestamp": timestamp.isoformat(),
            "raw_line": line,
            "event_type": event_type,
            "classification": classification,
            "user": groups.get("user", "unknown"),
            "source_ip": groups.get("ip", "unknown"),
            "service": "ssh",
            "hostname": "localhost",
            "success": classification == "auth_success",
            "metadata": {k: v for k, v in groups.items() if k not in ["month", "day", "time", "user", "ip"]},
            "severity": self._calculate_severity(classification, event_type)
        }
    
    def _calculate_severity(self, classification: str, event_type: str) -> str:
        """Calculate event severity"""
        
        if classification == "privilege_escalation":
            return "HIGH"
        elif "failed" in event_type.lower():
            return "MEDIUM"
        elif "invalid_user" in event_type:
            return "MEDIUM"
        else:
            return "LOW"