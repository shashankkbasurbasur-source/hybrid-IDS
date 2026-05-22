from backend.parsing.ssh_parser import SSHLogParser


class LogIngestor:
    """
    Handles ingestion of raw log files (HIDS)
    """

    def __init__(self):
        self.parsers = {
            "ssh": SSHLogParser()
        }

    def ingest_file(self, filepath, source="ssh"):
        """
        Read log file → return normalized events
        """
        parser = self.parsers.get(source)

        if not parser:
            raise ValueError(f"No parser registered for source: {source}")

        events = []

        print(f"[HIDS] Reading logs from: {filepath}")

        try:
            with open(filepath, "r") as f:
                for line in f:
                    event = parser.parse_line(line)
                    if event:
                        events.append(event)

        except FileNotFoundError:
            print(f"[HIDS] File not found: {filepath}")
            return []

        print(f"[HIDS] Parsed {len(events)} events.")
        return events