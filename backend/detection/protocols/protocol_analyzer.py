"""
Protocol Analyzer
Tracks packet/byte counts and active connections per protocol,
persisted to protocol_statistics.
"""

import threading
from datetime import datetime, timezone

from backend.storage.db_store import upsert_protocol_stat, fetch_protocol_statistics
from backend.core.logger import get_logger

logger = get_logger(__name__)

TRACKED_PROTOCOLS = {"TCP", "UDP", "ICMP", "ARP", "DNS", "DHCP", "HTTP", "HTTPS", "FTP", "SSH", "SMTP", "NTP"}


class ProtocolAnalyzer:
    def __init__(self):
        self._lock = threading.Lock()
        self._buffer = {}  # protocol -> {"packets": n, "bytes": n}

    def update(self, packet_event: dict):
        protocol = packet_event.get("protocol", "OTHER")
        dst_port = packet_event.get("dst_port")

        # Refine well-known ports into named app protocols where the parser
        # only identified the transport layer (TCP/UDP)
        port_map = {20: "FTP", 21: "FTP", 22: "SSH", 25: "SMTP", 123: "NTP",
                    80: "HTTP", 443: "HTTPS"}
        if protocol in ("TCP", "UDP") and dst_port in port_map:
            protocol = port_map[dst_port]

        length = packet_event.get("length", 0) or 0

        with self._lock:
            entry = self._buffer.setdefault(protocol, {"packets": 0, "bytes": 0})
            entry["packets"] += 1
            entry["bytes"] += length

    def flush(self):
        with self._lock:
            if not self._buffer:
                return
            batch = dict(self._buffer)
            self._buffer.clear()

        now = datetime.now(timezone.utc).isoformat()
        for protocol, counts in batch.items():
            try:
                upsert_protocol_stat(protocol, counts["packets"], counts["bytes"], now)
            except Exception as e:
                logger.error(f"Protocol stat upsert failed for {protocol}: {e}")

    def summary(self):
        stats = fetch_protocol_statistics()
        total_packets = sum(s["packets"] for s in stats) or 1
        for s in stats:
            s["percentage"] = round((s["packets"] / total_packets) * 100, 2)
        return stats


protocol_analyzer = ProtocolAnalyzer()