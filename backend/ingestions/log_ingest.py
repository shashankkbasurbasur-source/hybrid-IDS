from backend.parsing.ssh_parser import SSHLogParser

class LogIngestor:
    """
    Handles ingestion of raw log files
    """

    def __init__(self):
        self.parsers = {
            "ssh": SSHLogParser()
        }

    def ingest_file(self, filepath, source="ssh"):
        events = []
        parser = self.parsers.get(source)

        if not parser:
            raise ValueError(f"No parser registered for source: {source}")

        with open(filepath, "r") as f:
            for line in f:
                event = parser.parse_line(line)
                if event:
                    events.append(event)

        return events
