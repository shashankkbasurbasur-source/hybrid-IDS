"""
Live Network Packet Capture with Flow Building
"""

import socket
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
import threading

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import psutil


class NetworkFlow:
    """Represents a bidirectional network flow"""
    
    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        self.packet_count = 0
        self.byte_count = 0
        self.packets = []
        self.start_time = datetime.now()
        self.last_packet_time = self.start_time
        
        self.flags = set()
        self.destinations = set()
        self.sources = set()
        
    def add_packet(self, packet_data: Dict):
        """Add packet to flow"""
        self.packet_count += 1
        self.byte_count += packet_data.get("length", 0)
        self.packets.append(packet_data)
        self.last_packet_time = datetime.now()
        
        if packet_data.get("flags"):
            self.flags.add(packet_data["flags"])
        
        self.destinations.add(packet_data.get("dst_ip", ""))
        self.sources.add(packet_data.get("src_ip", ""))
    
    def duration(self) -> float:
        """Flow duration in seconds"""
        return (self.last_packet_time - self.start_time).total_seconds()
    
    def is_active(self, timeout: int = 30) -> bool:
        """Check if flow is still active"""
        return (datetime.now() - self.last_packet_time).total_seconds() < timeout


class FlowBuilder:
    """Builds bidirectional flows from packets"""
    
    def __init__(self, flow_timeout: int = 30):
        self.flows = {}
        self.flow_timeout = flow_timeout
        self.lock = threading.Lock()
    
    def get_flow_key(self, src_ip: str, dst_ip: str, src_port: int, 
                     dst_port: int, protocol: str) -> str:
        """Create bidirectional flow key"""
        ips = tuple(sorted([src_ip, dst_ip]))
        ports = tuple(sorted([src_port, dst_port]))
        return f"{ips[0]}:{ips[1]}:{ports[0]}:{ports[1]}:{protocol}"
    
    def add_packet(self, packet_data: Dict) -> str:
        """Add packet to flow, return flow key"""
        with self.lock:
            flow_key = self.get_flow_key(
                packet_data["src_ip"],
                packet_data["dst_ip"],
                packet_data["src_port"],
                packet_data["dst_port"],
                packet_data["protocol"]
            )
            
            if flow_key not in self.flows:
                self.flows[flow_key] = NetworkFlow(
                    packet_data["src_ip"],
                    packet_data["dst_ip"],
                    packet_data["src_port"],
                    packet_data["dst_port"],
                    packet_data["protocol"]
                )
            
            self.flows[flow_key].add_packet(packet_data)
            return flow_key
    
    def get_completed_flows(self) -> List[Tuple[str, NetworkFlow]]:
        """Get flows that have timed out"""
        with self.lock:
            completed = [
                (key, flow) for key, flow in self.flows.items()
                if not flow.is_active(self.flow_timeout)
            ]
            
            for key, _ in completed:
                del self.flows[key]
            
            return completed
    
    def get_active_flows(self) -> Dict[str, NetworkFlow]:
        """Get currently active flows"""
        with self.lock:
            return dict(self.flows)


class NetworkIngestor:
    """Live network packet ingestion with flow building"""
    
    def __init__(self, interface: str = None, packet_count: int = None):
        """
        Args:
            interface: Network interface (eth0, wlan0, etc.)
            packet_count: Max packets to capture (None = continuous)
        """
        self.interface = interface or self._get_default_interface()
        self.packet_count = packet_count
        self.flow_builder = FlowBuilder(flow_timeout=30)
        self.captured_packets = []
        self.is_capturing = False
        
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for packet capture. Install with: pip install scapy")
    
    def _get_default_interface(self) -> str:
        """Auto-detect the primary network interface"""
        try:
            interfaces = psutil.net_if_stats()
            for iface, stats in interfaces.items():
                if stats.isup and iface not in ["lo", "docker0"]:
                    return iface
        except:
            pass
        return "eth0"
    
    def _parse_packet(self, packet) -> Dict:
        """Convert raw packet to structured event"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": "0.0.0.0",
            "dst_ip": "0.0.0.0",
            "src_port": 0,
            "dst_port": 0,
            "protocol": "OTHER",
            "length": len(packet),
            "ttl": 0,
            "flags": None,
            "info": ""
        }
        
        try:
            if IP in packet:
                event["src_ip"] = packet[IP].src
                event["dst_ip"] = packet[IP].dst
                event["ttl"] = packet[IP].ttl
            
            if TCP in packet:
                event["protocol"] = "TCP"
                event["src_port"] = packet[TCP].sport
                event["dst_port"] = packet[TCP].dport
                event["flags"] = int(packet[TCP].flags)
                event["info"] = f"TCP {packet[TCP].sport}->{packet[TCP].dport}"
            
            elif UDP in packet:
                event["protocol"] = "UDP"
                event["src_port"] = packet[UDP].sport
                event["dst_port"] = packet[UDP].dport
                event["info"] = f"UDP {packet[UDP].sport}->{packet[UDP].dport}"
            
            elif ICMP in packet:
                event["protocol"] = "ICMP"
                event["info"] = f"ICMP Type:{packet[ICMP].type}"
            
            elif ARP in packet:
                event["protocol"] = "ARP"
                event["info"] = f"ARP {packet[ARP].op}"
        
        except Exception as e:
            event["error"] = str(e)
        
        return event
    
    def capture_live(self, duration: int = 30):
        """Capture packets for specified duration"""
        print(f"[NIDS] Capturing on interface: {self.interface} for {duration}s")
        
        self.is_capturing = True
        self.captured_packets = []
        
        def packet_callback(packet):
            if not self.is_capturing:
                return False
            
            event = self._parse_packet(packet)
            self.captured_packets.append(event)
            
            # Add to flow builder
            self.flow_builder.add_packet(event)
        
        try:
            sniff(
                prn=packet_callback,
                iface=self.interface,
                timeout=duration,
                store=False
            )
        except PermissionError:
            raise RuntimeError(f"Root privileges required for packet capture on {self.interface}")
        finally:
            self.is_capturing = False
        
        return self.captured_packets
    
    def get_active_flows_snapshot(self) -> List[Dict]:
        """Get current active flows as feature-ready structures"""
        flows = self.flow_builder.get_active_flows()
        
        flow_summaries = []
        for flow_key, flow in flows.items():
            flow_summaries.append({
                "flow_key": flow_key,
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "protocol": flow.protocol,
                "packet_count": flow.packet_count,
                "byte_count": flow.byte_count,
                "duration": flow.duration(),
                "unique_dports": len(flow.destinations),
                "unique_sports": len(flow.sources),
                "flags": list(flow.flags)
            })
        
        return flow_summaries
    
    def get_capture_stats(self) -> Dict:
        """Get current capture statistics"""
        return {
            "packets_captured": len(self.captured_packets),
            "interface": self.interface,
            "is_capturing": self.is_capturing,
            "active_flows": len(self.flow_builder.flows),
            "tcp_count": sum(1 for p in self.captured_packets if p["protocol"] == "TCP"),
            "udp_count": sum(1 for p in self.captured_packets if p["protocol"] == "UDP"),
            "icmp_count": sum(1 for p in self.captured_packets if p["protocol"] == "ICMP"),
            "arp_count": sum(1 for p in self.captured_packets if p["protocol"] == "ARP"),
        }