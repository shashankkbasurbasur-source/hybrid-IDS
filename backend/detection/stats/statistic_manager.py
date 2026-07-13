"""
Statistics Manager
Tracks live capture statistics in memory; NetworkIngestor periodically
snapshots this to the capture_statistics table.
"""

import threading
import time
from datetime import datetime, timezone

from backend.storage.db_store import insert_statistics_snapshot
from backend.core.logger import get_logger

logger = get_logger(__name__)


class StatisticsManager:
    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self):
        with self._lock:
            self._start_time = time.monotonic()
            self.total_packets = 0
            self.total_bytes = 0
            self.tcp_count = 0
            self.udp_count = 0
            self.icmp_count = 0
            self.arp_count = 0
            self.dropped_packets = 0
            self.parsing_errors = 0
            self._last_snapshot_packets = 0
            self._last_snapshot_bytes = 0
            self._last_snapshot_time = self._start_time

    def update(self, packet_event: dict):
        with self._lock:
            self.total_packets += 1
            self.total_bytes += packet_event.get("length", 0) or 0

            proto = packet_event.get("protocol")
            if proto == "TCP":
                self.tcp_count += 1
            elif proto == "UDP":
                self.udp_count += 1
            elif proto == "ICMP":
                self.icmp_count += 1
            elif proto == "ARP":
                self.arp_count += 1

            if packet_event.get("parse_error"):
                self.parsing_errors += 1

    def record_drop(self):
        with self._lock:
            self.dropped_packets += 1

    def snapshot(self, session_id: str, active_flows: int, active_devices: int) -> dict:
        with self._lock:
            now = time.monotonic()
            elapsed = max(now - self._last_snapshot_time, 0.001)

            pps = (self.total_packets - self._last_snapshot_packets) / elapsed
            bps = (self.total_bytes - self._last_snapshot_bytes) / elapsed

            self._last_snapshot_packets = self.total_packets
            self._last_snapshot_bytes = self.total_bytes
            self._last_snapshot_time = now

            data = {
                "session_id": session_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "total_packets": self.total_packets,
                "packets_per_sec": round(pps, 2),
                "bytes_per_sec": round(bps, 2),
                "total_bytes": self.total_bytes,
                "active_flows": active_flows,
                "active_devices": active_devices,
                "tcp_count": self.tcp_count,
                "udp_count": self.udp_count,
                "icmp_count": self.icmp_count,
                "arp_count": self.arp_count,
                "dropped_packets": self.dropped_packets,
                "parsing_errors": self.parsing_errors,
            }

        try:
            insert_statistics_snapshot(data)
        except Exception as e:
            logger.error(f"Statistics snapshot write failed: {e}")

        return data

    def duration_seconds(self) -> float:
        with self._lock:
            return time.monotonic() - self._start_time

    def as_dict(self) -> dict:
        with self._lock:
            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "tcp_count": self.tcp_count,
                "udp_count": self.udp_count,
                "icmp_count": self.icmp_count,
                "arp_count": self.arp_count,
                "dropped_packets": self.dropped_packets,
                "parsing_errors": self.parsing_errors,
                "duration_seconds": round(self.duration_seconds(), 2),
            }


statistics_manager = StatisticsManager()