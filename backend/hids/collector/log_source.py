"""
Unified Log Input Interface — every HIDS log source (live tail,
manual upload, and future Syslog/Windows Event Log sources) implements
this and yields the same normalized event shape produced by
AuthLogParser. Everything downstream (the detector) is source-agnostic.
"""


class LogSource:
    def events(self):
        """Yields normalized event dicts. Must be implemented by subclasses."""
        raise NotImplementedError