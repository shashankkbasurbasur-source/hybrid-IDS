import os
from backend.hids.collector.log_watcher import LogFileWatcher
from backend.hids.collector.syscall_parser import SyscallLogParser

DEFAULT_AUDIT_LOG = "/var/log/audit/audit.log"


class SyscallLogSource:
    def __init__(self, log_path: str = DEFAULT_AUDIT_LOG, poll_interval: float = 1.0):
        if not os.path.exists(log_path):
            raise FileNotFoundError(
                f"{log_path} not found. Is auditd installed and running? (systemctl status auditd)"
            )
        self.log_path = log_path
        self.parser = SyscallLogParser()
        self.watcher = LogFileWatcher(log_path, poll_interval=poll_interval)

    def events(self):
        for line in self.watcher.tail():
            event = self.parser.parse_line(line)
            if event:
                yield event

    def stop(self):
        self.watcher.stop()