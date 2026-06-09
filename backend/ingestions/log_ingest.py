# backend/ingestions/log_ingest.py

from backend.parsing.ssh_parser import SSHLogParser
from backend.core.logger        import get_logger

logger = get_logger(__name__)


class LogIngestor:
    """Handles ingestion of raw log files and raw log strings (HIDS)."""

    def __init__(self):
        self.parsers = {
            "ssh": SSHLogParser()
        }

    def ingest_file(self, filepath: str, source: str = "ssh") -> list:
        """Read log file → return normalized events."""
        parser = self.parsers.get(source)
        if not parser:
            raise ValueError(f"No parser for source: {source}")

        events = []
        logger.info("[HIDS] Reading logs from: %s", filepath)

        try:
            with open(filepath, "r") as f:
                for line in f:
                    event = parser.parse_line(line)
                    if event:
                        events.append(event)
        except FileNotFoundError:
            logger.warning("[HIDS] File not found: %s", filepath)
            return []

        logger.info("[HIDS] Parsed %d events", len(events))
        return events

    def ingest_lines(self, lines: list, source: str = "ssh") -> list:
        """Accept a list of raw log strings → return normalized events."""
        parser = self.parsers.get(source)
        if not parser:
            raise ValueError(f"No parser for source: {source}")

        events = []
        for line in lines:
            event = parser.parse_line(line)
            if event:
                events.append(event)

        logger.info("[HIDS] Parsed %d events from %d lines", len(events), len(lines))
        return events