"""
Manual/forensic log source (Mode 2). Reads a finite uploaded log file
once, yields normalized events through the same parser as the live
source.
"""

from backend.hids.collector.parser import AuthLogParser
from backend.hids.collector.log_source import LogSource


class UploadedLogSource(LogSource):
    def __init__(self, file_path):
        self.file_path = file_path
        self.parser = AuthLogParser()

    def events(self):
        with open(self.file_path, "r") as f:
            for line in f:
                event = self.parser.parse_line(line)
                if event:
                    yield event