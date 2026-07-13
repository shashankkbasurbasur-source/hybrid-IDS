"""
Live authentication log source (Mode 1). Auto-detects the distro's
auth log path, tails it continuously, yields normalized events through
the same parser used by the manual upload source.
"""

import os

from backend.hids.collector.log_watcher import LogFileWatcher
from backend.hids.collector.parser import AuthLogParser
from backend.hids.collector.log_source import LogSource

_CANDIDATE_PATHS = [
    "/var/log/auth.log",   # Ubuntu / Debian
    "/var/log/secure",     # CentOS / RHEL
]


def detect_auth_log_path(override=None):
    if override:
        return override
    for path in _CANDIDATE_PATHS:
        if os.path.exists(path):
            return path
    raise FileNotFoundError(
        "Could not locate an authentication log. Checked: "
        + ", ".join(_CANDIDATE_PATHS)
        + ". On Windows, use the Windows Event Log collector (not yet implemented)."
    )


class AuthLogSource(LogSource):
    def __init__(self, log_path=None, poll_interval=1.0):
        self.log_path = detect_auth_log_path(log_path)
        self.parser = AuthLogParser()
        self.watcher = LogFileWatcher(self.log_path, poll_interval=poll_interval)

    def events(self):
        for line in self.watcher.tail():
            event = self.parser.parse_line(line)
            if event:
                yield event

    def stop(self):
        self.watcher.stop()


# Backwards-compatible alias
AuthLogMonitor = AuthLogSource