"""
Flow Manager — final version.
Retains raw packet-level data (lengths, timestamps, flags, headers, window
sizes, bulk state) so FeatureExtractionEngine can compute exact CICIDS2017
feature formulas, rather than pre-aggregating into lossy running stats.
"""

import threading
import time
import uuid
from datetime import datetime, timezone

from backend.storage.db_store import upsert_flow
from backend.detection.queues.feature_extraction_queue import feature_extraction_queue
from backend.core.logger import get_logger

logger = get_logger(__name__)

FLOW_IDLE_TIMEOUT_SECONDS = 30
ACTIVE_GAP_THRESHOLD_SECONDS = 1.0   # gap below this = still "active" burst
BULK_GAP_THRESHOLD_SECONDS = 1.0     # gap below this = same bulk episode
BULK_MIN_PACKETS = 4                 # minimum packets to count as a "bulk"
MAX_RAW_SAMPLES_PER_FLOW = 100000    # safety cap against unbounded memory growth

FLAG_BITS = {"FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08,
             "ACK": 0x10, "URG": 0x20, "ECE": 0x40, "CWE": 0x80}


class FlowManager:
    def __init__(self, idle_timeout_seconds: int = FLOW_IDLE_TIMEOUT_SECONDS):
        self._lock = threading.Lock()
        self._active_flows = {}
        self._idle_timeout_seconds = idle_timeout_seconds

    def _flow_key(self, src_ip, dst_ip, src_port, dst_port, protocol) -> str:
        return "|".join(str(x) for x in (src_ip, dst_ip, src_port, dst_port, protocol))

    def _direction_is_internal(self, ip: str) -> bool:
        private_prefixes = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                            "172.19.", "172.2", "172.3")
        return bool(ip) and ip.startswith(private_prefixes)

    def _new_flow(self, key, src_ip, dst_ip, src_port, dst_port, protocol, now_iso, now_mono):
        return {
            "flow_id": str(uuid.uuid4()),
            "flow_key": key,
            "src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": src_port, "dst_port": dst_port,
            "protocol": protocol,
            "first_seen": now_iso, "last_seen": now_iso,
            "direction": "internal" if self._direction_is_internal(src_ip) else "outgoing",
            "status": "ACTIVE",

            # Aggregate counters (used for the `flows` SQLite table only)
            "packet_count": 0, "byte_count": 0,
            "fwd_packets": 0, "bwd_packets": 0,
            "fwd_bytes": 0, "bwd_bytes": 0,
            "_delta_packet_count": 0, "_delta_byte_count": 0,
            "_delta_fwd": 0, "_delta_bwd": 0,

            # Raw packet-level data (used by FeatureExtractionEngine)
            "packet_lengths": [], "fwd_packet_lengths": [], "bwd_packet_lengths": [],
            "packet_timestamps": [], "fwd_timestamps": [], "bwd_timestamps": [],
            "fwd_header_lengths": [], "bwd_header_lengths": [],

            "flag_counts": {"SYN": 0, "ACK": 0, "FIN": 0, "RST": 0, "ECE": 0, "CWE": 0},
            "fwd_psh_count": 0, "bwd_psh_count": 0,
            "fwd_urg_count": 0, "bwd_urg_count": 0,

            "init_win_fwd": None, "init_win_bwd": None,
            "fwd_data_pkt_count": 0,  # act_data_pkt_fwd

            "active_times": [], "idle_times": [],
            "_current_active_start": now_mono,
            "_last_activity_mono": now_mono,

            # Bulk detection state (streaming, per direction)
            "_fwd_bulk_state": {"start": None, "last_ts": None, "count": 0, "bytes": 0},
            "_bwd_bulk_state": {"start": None, "last_ts": None, "count": 0, "bytes": 0},
            "fwd_bulk_total_bytes": 0, "fwd_bulk_total_packets": 0,
            "fwd_bulk_count": 0, "fwd_bulk_total_duration": 0.0,
            "bwd_bulk_total_bytes": 0, "bwd_bulk_total_packets": 0,
            "bwd_bulk_count": 0, "bwd_bulk_total_duration": 0.0,
        }

    def _update_flags(self, flow: dict, flags_int: int, is_forward: bool):
        if not flags_int:
            return
        for name, bit in FLAG_BITS.items():
            if flags_int & bit and name not in ("PSH", "URG"):
                flow["flag_counts"][name] += 1
        if flags_int & FLAG_BITS["PSH"]:
            flow["fwd_psh_count" if is_forward else "bwd_psh_count"] += 1
        if flags_int & FLAG_BITS["URG"]:
            flow["fwd_urg_count" if is_forward else "bwd_urg_count"] += 1

    def _update_bulk(self, flow: dict, is_forward: bool, now_mono: float, length: int):
        state_key = "_fwd_bulk_state" if is_forward else "_bwd_bulk_state"
        state = flow[state_key]

        if state["last_ts"] is not None and (now_mono - state["last_ts"]) <= BULK_GAP_THRESHOLD_SECONDS:
            state["count"] += 1
            state["bytes"] += length
        else:
            self._finalize_bulk(flow, is_forward)
            state["start"] = now_mono
            state["count"] = 1
            state["bytes"] = length

        state["last_ts"] = now_mono

    def _finalize_bulk(self, flow: dict, is_forward: bool):
        state_key = "_fwd_bulk_state" if is_forward else "_bwd_bulk_state"
        prefix = "fwd" if is_forward else "bwd"
        state = flow[state_key]

        if state["count"] >= BULK_MIN_PACKETS and state["start"] is not None:
            duration = max((state["last_ts"] or state["start"]) - state["start"], 0.0)
            flow[f"{prefix}_bulk_total_bytes"] += state["bytes"]
            flow[f"{prefix}_bulk_total_packets"] += state["count"]
            flow[f"{prefix}_bulk_count"] += 1
            flow[f"{prefix}_bulk_total_duration"] += duration

        state["start"] = None
        state["last_ts"] = None
        state["count"] = 0
        state["bytes"] = 0

    def update(self, packet_event: dict):
        src_ip = packet_event.get("src_ip")
        dst_ip = packet_event.get("dst_ip")
        if not src_ip or not dst_ip:
            return

        key = self._flow_key(src_ip, dst_ip, packet_event.get("src_port"),
                              packet_event.get("dst_port"), packet_event.get("protocol"))
        reverse_key = self._flow_key(dst_ip, src_ip, packet_event.get("dst_port"),
                                      packet_event.get("src_port"), packet_event.get("protocol"))

        now_iso = datetime.now(timezone.utc).isoformat()
        now_mono = time.monotonic()
        length = packet_event.get("length", 0) or 0
        header_len = (packet_event.get("header_length", 0) or 0) + \
                     (packet_event.get("tcp_header_length", 0) or 0)

        with self._lock:
            existing_key = key if key in self._active_flows else (
                reverse_key if reverse_key in self._active_flows else key
            )
            is_forward = existing_key == key

            flow = self._active_flows.get(existing_key)
            if flow is None:
                flow = self._new_flow(existing_key, src_ip, dst_ip,
                                       packet_event.get("src_port"), packet_event.get("dst_port"),
                                       packet_event.get("protocol"), now_iso, now_mono)
                self._active_flows[existing_key] = flow
                logger.info(f"New flow created: {existing_key}")
            else:
                gap = now_mono - flow["_last_activity_mono"]
                if gap >= ACTIVE_GAP_THRESHOLD_SECONDS:
                    active_duration = flow["_last_activity_mono"] - flow["_current_active_start"]
                    if active_duration > 0:
                        flow["active_times"].append(active_duration)
                    flow["idle_times"].append(gap)
                    flow["_current_active_start"] = now_mono

            flow["last_seen"] = now_iso
            flow["_last_activity_mono"] = now_mono
            flow["packet_count"] += 1
            flow["byte_count"] += length
            flow["_delta_packet_count"] += 1
            flow["_delta_byte_count"] += length

            under_cap = len(flow["packet_lengths"]) < MAX_RAW_SAMPLES_PER_FLOW
            if under_cap:
                flow["packet_lengths"].append(length)
                flow["packet_timestamps"].append(now_mono)

            self._update_flags(flow, packet_event.get("flags", 0) or 0, is_forward)

            if is_forward:
                flow["fwd_packets"] += 1
                flow["fwd_bytes"] += length
                flow["_delta_fwd"] += 1
                if under_cap:
                    flow["fwd_packet_lengths"].append(length)
                    flow["fwd_timestamps"].append(now_mono)
                    flow["fwd_header_lengths"].append(header_len)
                if flow["init_win_fwd"] is None:
                    flow["init_win_fwd"] = packet_event.get("window_size", 0) or 0
                if length > header_len:
                    flow["fwd_data_pkt_count"] += 1
                self._update_bulk(flow, True, now_mono, length)
            else:
                flow["bwd_packets"] += 1
                flow["bwd_bytes"] += length
                flow["_delta_bwd"] += 1
                if under_cap:
                    flow["bwd_packet_lengths"].append(length)
                    flow["bwd_timestamps"].append(now_mono)
                    flow["bwd_header_lengths"].append(header_len)
                if flow["init_win_bwd"] is None:
                    flow["init_win_bwd"] = packet_event.get("window_size", 0) or 0
                self._update_bulk(flow, False, now_mono, length)

    def _finalize_flow(self, flow: dict):
        """Closes out any open active burst and open bulk episodes before completion."""
        active_duration = flow["_last_activity_mono"] - flow["_current_active_start"]
        if active_duration > 0:
            flow["active_times"].append(active_duration)
        self._finalize_bulk(flow, True)
        self._finalize_bulk(flow, False)

    def check_timeouts(self):
        now_mono = time.monotonic()
        completed_flows = []

        with self._lock:
            for key, flow in list(self._active_flows.items()):
                if now_mono - flow["_last_activity_mono"] >= self._idle_timeout_seconds:
                    self._finalize_flow(flow)
                    flow["status"] = "COMPLETED"
                    completed_flows.append(flow)
                    del self._active_flows[key]

        for flow in completed_flows:
            try:
                feature_extraction_queue.enqueue(flow)
            except Exception as e:
                logger.error(f"Failed to enqueue completed flow {flow['flow_key']}: {e}")
            logger.info(f"Flow completed and archived: {flow['flow_key']}")

    def flush(self):
        """Persists ACTIVE flows' aggregate deltas to SQLite (not the raw lists)."""
        with self._lock:
            if not self._active_flows:
                return
            batch = []
            for flow in self._active_flows.values():
                if flow["_delta_packet_count"] == 0:
                    continue
                batch.append({
                    "flow_id": flow["flow_id"], "flow_key": flow["flow_key"],
                    "src_ip": flow["src_ip"], "dst_ip": flow["dst_ip"],
                    "src_port": flow["src_port"], "dst_port": flow["dst_port"],
                    "protocol": flow["protocol"],
                    "first_seen": flow["first_seen"], "last_seen": flow["last_seen"],
                    "packet_count": flow["_delta_packet_count"], "byte_count": flow["_delta_byte_count"],
                    "fwd_packets": flow["_delta_fwd"], "bwd_packets": flow["_delta_bwd"],
                    "active_time": sum(flow["active_times"]),
                    "idle_time": sum(flow["idle_times"]),
                    "status": flow["status"],
                })
                flow["_delta_packet_count"] = 0
                flow["_delta_byte_count"] = 0
                flow["_delta_fwd"] = 0
                flow["_delta_bwd"] = 0

        for row in batch:
            try:
                upsert_flow(row)
            except Exception as e:
                logger.error(f"Flow upsert failed for {row['flow_key']}: {e}")

    def force_flush_all(self):
        with self._lock:
            remaining = list(self._active_flows.values())
            self._active_flows.clear()

        for flow in remaining:
            self._finalize_flow(flow)
            flow["status"] = "COMPLETED"
            try:
                feature_extraction_queue.enqueue(flow)
            except Exception as e:
                logger.error(f"Failed to enqueue flow on shutdown {flow['flow_key']}: {e}")

        self.flush()
        logger.info(f"Force-flushed {len(remaining)} active flows on shutdown")

    def active_flow_count(self) -> int:
        with self._lock:
            return len(self._active_flows)


flow_manager = FlowManager()