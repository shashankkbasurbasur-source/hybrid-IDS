# backend/parsing/ssh_parser.py
import re

class SSHLogParser:
    """
    Parser for Linux SSH authentication logs.
    Outputs normalized security events.
    """

    FAILED_REGEX = re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*'
        r'Failed password for (invalid user )?(?P<user>\w+) from (?P<ip>[\d.]+)'
    )

    SUCCESS_REGEX = re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*'
        r'Accepted password for (?P<user>\w+) from (?P<ip>[\d.]+)'
    )

    def parse_line(self, line: str):
        line = line.strip()
        m = self.FAILED_REGEX.search(line)
        if m:
            return {
                "timestamp": f"{m.group('month')} {m.group('day')} {m.group('time')}",
                "source": "ssh",
                "event_type": "auth_fail",
                "user": m.group("user"),
                "ip": m.group("ip"),
                "raw": line
            }

        m = self.SUCCESS_REGEX.search(line)
        if m:
            return {
                "timestamp": f"{m.group('month')} {m.group('day')} {m.group('time')}",
                "source": "ssh",
                "event_type": "auth_success",
                "user": m.group("user"),
                "ip": m.group("ip"),
                "raw": line
            }

        return None