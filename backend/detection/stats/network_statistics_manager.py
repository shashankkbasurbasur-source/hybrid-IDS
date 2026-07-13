"""
Network Statistics Manager
Aggregates data FROM StatisticsManager (Step 2), FlowManager, DeviceManager,
and ProtocolAnalyzer into the higher-level "network intelligence" metrics
the dashboard reads: averages, connection-type counts, DNS/ARP request totals.
"""

from datetime import datetime, timezone

from backend.detection.stats.statistic_manager import statistics_manager
from backend.detection.flows.flow_manager import flow_manager
from backend.detection.devices.device_manager import device_manager
from backend.detection.protocols.protocol_analyzer import protocol_analyzer
from backend.storage.db_store import insert_network_statistics, fetch_protocol_statistics
from backend.core.logger import get_logger

logger = get_logger(__name__)


class NetworkStatisticsManager:
    def build_snapshot(self, session_id: str) -> dict:
        base = statistics_manager.as_dict()
        protocol_stats = {p["protocol"]: p for p in fetch_protocol_statistics()}

        total_packets = base["total_packets"] or 1
        avg_packet_size = base["total_bytes"] / total_packets

        duration = base["duration_seconds"] or 0.001
        pps = base["total_packets"] / duration
        bps = base["total_bytes"] / duration

        snapshot = {
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_packets": base["total_packets"],
            "total_bytes": base["total_bytes"],
            "active_devices": device_manager.active_device_count(),
            "active_flows": flow_manager.active_flow_count(),
            "pps": round(pps, 2),
            "bps": round(bps, 2),
            "avg_packet_size": round(avg_packet_size, 2),
            "avg_flow_duration": 0.0,  # populated from completed flows in Step 4+ if needed
            "tcp_connections": protocol_stats.get("TCP", {}).get("packets", 0),
            "udp_connections": protocol_stats.get("UDP", {}).get("packets", 0),
            "dns_requests": protocol_stats.get("DNS", {}).get("packets", 0),
            "arp_requests": protocol_stats.get("ARP", {}).get("packets", 0),
            "capture_duration": round(duration, 2),
        }

        try:
            insert_network_statistics(snapshot)
        except Exception as e:
            logger.error(f"Failed to persist network statistics snapshot: {e}")

        return snapshot


network_statistics_manager = NetworkStatisticsManager()