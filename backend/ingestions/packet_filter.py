"""
Packet Filter Manager
Applies optional BPF filters (passed straight to Scapy/AsyncSniffer) plus
post-capture protocol/IP/port filters for finer control without touching
the parser. Sits conceptually between the sniffer and the parser.
"""

from backend.core.logger import get_logger

logger = get_logger(__name__)


class PacketFilterManager:
    def __init__(self):
        self._bpf_filter = None          # passed to AsyncSniffer(filter=...)
        self._protocol_filter = None     # e.g. {"TCP", "UDP"}
        self._ip_filter = None           # e.g. {"192.168.1.5"}
        self._port_filter = None         # e.g. {80, 443}
        self._enabled = True

    # -----------------------------
    # Configuration
    # -----------------------------
    def set_bpf_filter(self, bpf: str | None):
        self._bpf_filter = bpf.strip() if bpf else None
        logger.info(f"BPF filter set to: {self._bpf_filter}")

    def set_protocol_filter(self, protocols: list | None):
        self._protocol_filter = set(p.upper() for p in protocols) if protocols else None

    def set_ip_filter(self, ips: list | None):
        self._ip_filter = set(ips) if ips else None

    def set_port_filter(self, ports: list | None):
        self._port_filter = set(int(p) for p in ports) if ports else None

    def enable(self):
        self._enabled = True

    def disable(self):
        self._enabled = False

    def get_bpf_filter(self) -> str | None:
        """Used directly by AsyncSniffer(filter=...) at capture start."""
        return self._bpf_filter

    def clear_all(self):
        self._bpf_filter = None
        self._protocol_filter = None
        self._ip_filter = None
        self._port_filter = None

    def current_config(self) -> dict:
        return {
            "enabled": self._enabled,
            "bpf_filter": self._bpf_filter,
            "protocol_filter": list(self._protocol_filter) if self._protocol_filter else None,
            "ip_filter": list(self._ip_filter) if self._ip_filter else None,
            "port_filter": list(self._port_filter) if self._port_filter else None,
        }

    # -----------------------------
    # Post-parse filtering (protocol/IP/port — applied to the parsed event,
    # cheaper than re-parsing and lets us filter on things BPF can't easily express)
    # -----------------------------
    def passes(self, event: dict) -> bool:
        if not self._enabled:
            return True

        if self._protocol_filter and event.get("protocol") not in self._protocol_filter:
            return False

        if self._ip_filter:
            if event.get("src_ip") not in self._ip_filter and event.get("dst_ip") not in self._ip_filter:
                return False

        if self._port_filter:
            if event.get("src_port") not in self._port_filter and event.get("dst_port") not in self._port_filter:
                return False

        return True


packet_filter_manager = PacketFilterManager()