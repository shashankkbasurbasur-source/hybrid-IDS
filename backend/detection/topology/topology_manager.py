"""
Network Topology Builder
Builds a simple graph purely from observed device_connections — no active
scanning. Identifies the likely gateway using InterfaceManager's known
gateway IP (from Step 1) as the anchor node.
"""

from backend.storage.db_store import fetch_device_connections, fetch_devices
from backend.ingestions.interface_manager import interface_manager
from backend.core.logger import get_logger

logger = get_logger(__name__)


class TopologyManager:
    def build(self) -> dict:
        connections = fetch_device_connections(limit=1000)
        devices = {d["ip"]: d for d in fetch_devices()}

        gateway_ip = None
        try:
            current = interface_manager.current()
            gateway_ip = current["interface"].get("gateway")
            if gateway_ip == "N/A":
                gateway_ip = None
        except Exception:
            pass

        nodes = {}
        edges = []

        for conn in connections:
            src, dst = conn["src_device"], conn["dst_device"]
            for ip in (src, dst):
                if ip not in nodes:
                    device_info = devices.get(ip, {})
                    nodes[ip] = {
                        "ip": ip,
                        "hostname": device_info.get("hostname", "Unknown"),
                        "vendor": device_info.get("vendor", "Unknown"),
                        "status": device_info.get("status", "Unknown"),
                        "is_gateway": ip == gateway_ip,
                    }

            edges.append({
                "source": src,
                "target": dst,
                "communications": conn["communications"],
                "bytes_total": conn["bytes_total"],
            })

        return {
            "gateway": gateway_ip,
            "nodes": list(nodes.values()),
            "edges": edges,
        }


topology_manager = TopologyManager()