"""
Authentication Log Parser
==========================
Parses SSH authentication log lines (Ubuntu/Debian /var/log/auth.log,
CentOS/RHEL /var/log/secure — both use the same sshd message format,
they just live at different paths) into normalized event dicts.

This supersedes backend/parsing/ssh_parser.py: the old parser threw
away the auth method (password vs publickey), the invalid-user flag,
and the port — all of which are required by the new feature schema
(feature_schema.py). Nothing here changes the *matching* logic, it
just captures the fields that were already present in the log line
but previously discarded.

Normalized event shape:
{
    "timestamp": "May 10 11:01:01",
    "source": "ssh",
    "event_type": "auth_fail" | "auth_success",
    "user": "admin",
    "ip": "192.168.1.50",
    "port": 22,
    "auth_method": "password" | "publickey" | "unknown",
    "invalid_user": True | False,
    "raw": "<original line>"
}

"""

import re

class AuthLogParser:
    """
    Parser for Linux SSH authentication logs (auth.log / secure).
    Outputs normalized security events per the schema above.
    """

    # "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"
    # "Failed publickey for root from 1.2.3.4 port 22 ssh2"
    FAILED_REGEX = re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*'
        r'Failed (?P<method>password|publickey|keyboard-interactive) for '
        r'(?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)'
        r'(?: port (?P<port>\d+))?'
    )

    # "Accepted password for root from 1.2.3.4 port 22 ssh2"
    SUCCESS_REGEX = re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*'
        r'Accepted (?P<method>password|publickey|keyboard-interactive) for '
        r'(?P<user>\S+) from (?P<ip>[\d.]+)'
        r'(?: port (?P<port>\d+))?'
    )

    # Some distros log invalid users as a distinct line:
    # "Invalid user admin from 1.2.3.4 port 22"
    INVALID_USER_REGEX = re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*'
        r'Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)'
        r'(?: port (?P<port>\d+))?'
    )

    def parse_line(self, line: str):
        line = line.strip()
        if not line:
            return None

        m = self.FAILED_REGEX.search(line)
        if m:
            return {
                "timestamp": f"{m.group('month')} {m.group('day')} {m.group('time')}",
                "source": "ssh",
                "event_type": "auth_fail",
                "user": m.group("user"),
                "ip": m.group("ip"),
                "port": int(m.group("port")) if m.group("port") else 22,
                "auth_method": m.group("method") if m.group("method") in ("password", "publickey") else "unknown",
                "invalid_user": bool(m.group("invalid")),
                "raw": line,
            }

        m = self.SUCCESS_REGEX.search(line)
        if m:
            return {
                "timestamp": f"{m.group('month')} {m.group('day')} {m.group('time')}",
                "source": "ssh",
                "event_type": "auth_success",
                "user": m.group("user"),
                "ip": m.group("ip"),
                "port": int(m.group("port")) if m.group("port") else 22,
                "auth_method": m.group("method") if m.group("method") in ("password", "publickey") else "unknown",
                "invalid_user": False,
                "raw": line,
            }

        m = self.INVALID_USER_REGEX.search(line)
        if m:
            return {
                "timestamp": f"{m.group('month')} {m.group('day')} {m.group('time')}",
                "source": "ssh",
                "event_type": "auth_fail",
                "user": m.group("user"),
                "ip": m.group("ip"),
                "port": int(m.group("port")) if m.group("port") else 22,
                "auth_method": "unknown",
                "invalid_user": True,
                "raw": line,
            }

        return None

    def parse_lines(self, lines):
        """Parse an iterable of raw lines into a list of normalized events."""
        events = []
        for line in lines:
            event = self.parse_line(line)
            if event:
                events.append(event)
        return events


# Backwards-compatible alias: distro-specific paths differ, the log
# format and parsing logic do not, so auth.log and secure both use
# this same parser class.
SSHLogParser = AuthLogParser