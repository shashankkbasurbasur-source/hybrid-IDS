"""
Device Manager — final version (Step 3).
Tracks every device seen as source or destination, resolves hostname/vendor,
tracks incoming/outgoing packet split, and records device-to-device
communication via the connection tracker (Module 2).
"""

import hashlib
import threading
from datetime import datetime, timezone

from backend.storage.db_store import upsert_device, upsert_device_connection
from backend.detection.devices.vendor_lookup import lookup_vendor
from backend.detection.devices.hostname_lookup import get_hostname_async
from backend.core.logger import get_logger

logger = get_logger(__name__)


def _device_id(ip: str) -> str:
    """Deterministic short ID so the same IP always maps to the same device_id."""
    return hashlib.sha1(ip.encode()).hexdigest()[:12]


class DeviceManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._seen_this_flush = {}          # ip -> aggregated device dict
        self._connections_this_flush = {}   # (src, dst) -> aggregated connection dict

    def _touch(self, ip: str, mac: str, length: int, now: str,
               is_incoming: bool, interface: str):
        if not ip:
            return None

        entry = self._seen_this_flush.get(ip)
        if entry is None:
            entry = {
                "ip": ip,
                "mac": mac,
                "hostname": get_hostname_async(ip),  # never blocks; may return 'Unknown' first call
                "vendor": lookup_vendor(mac),
                "device_id": _device_id(ip),
                "interface": interface,
                "first_seen": now, "last_seen": now,
                "packet_count": 0, "bytes_total": 0,
                "incoming_packets": 0, "outgoing_packets": 0,
                "active_flows": 0,
                "status": "Online",
                "trust_score": "Unknown",  # Module 7 placeholder
            }
            self._seen_this_flush[ip] = entry
            logger.info(f"New device discovered: {ip} ({entry['vendor']})")

        entry["mac"] = mac or entry["mac"]
        entry["last_seen"] = now
        entry["packet_count"] += 1
        entry["bytes_total"] += length
        if is_incoming:
            entry["incoming_packets"] += 1
        else:
            entry["outgoing_packets"] += 1

        return entry

    def update(self, packet_event: dict):
        now = datetime.now(timezone.utc).isoformat()
        length = packet_event.get("length", 0) or 0
        src_ip = packet_event.get("src_ip")
        dst_ip = packet_event.get("dst_ip")
        interface = packet_event.get("interface")

        with self._lock:
            # Source device: this packet is outgoing FROM its perspective
            self._touch(src_ip, packet_event.get("eth_src"), length, now,
                        is_incoming=False, interface=interface)
            # Destination device: this packet is incoming TO its perspective
            self._touch(dst_ip, packet_event.get("eth_dst"), length, now,
                        is_incoming=True, interface=interface)

            # Device-to-device communication (Module 2 / Module 3 topology input)
            if src_ip and dst_ip:
                key = (src_ip, dst_ip)
                conn = self._connections_this_flush.get(key)
                if conn is None:
                    conn = {
                        "src_device": src_ip, "dst_device": dst_ip,
                        "first_seen": now, "last_seen": now,
                        "communications": 0, "bytes_total": 0,
                    }
                    self._connections_this_flush[key] = conn
                conn["last_seen"] = now
                conn["communications"] += 1
                conn["bytes_total"] += length

    def flush(self):
        with self._lock:
            device_batch = list(self._seen_this_flush.values())
            conn_batch = list(self._connections_this_flush.values())
            self._seen_this_flush.clear()
            self._connections_this_flush.clear()

        for device in device_batch:
            try:
                upsert_device(device)
            except Exception as e:
                logger.error(f"Device upsert failed for {device['ip']}: {e}")

        for conn in conn_batch:
            try:
                upsert_device_connection(conn)
            except Exception as e:
                logger.error(
                    f"Device connection upsert failed for "
                    f"{conn['src_device']}->{conn['dst_device']}: {e}"
                )

    def active_device_count(self) -> int:
        with self._lock:
            return len(self._seen_this_flush)


device_manager = DeviceManager()