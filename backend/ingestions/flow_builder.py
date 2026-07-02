"""
Advanced Flow Builder for NIDS
Groups packets into bidirectional flows
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import hashlib
import threading


class NetworkFlow:
    """Represents a bidirectional network flow"""
    
    def __init__(self, src_ip: str, dst_ip: str, src_port: int, 
                 dst_port: int, protocol: str):
        
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        # Generate flow ID
        self.flow_id = self._generate_flow_id()
        
        # Timing
        self.start_time = datetime.now()
        self.last_packet_time = self.start_time
        
        # Packet tracking
        self.packets = []
        self.packet_count = 0
        self.byte_count = 0
        self.iat_list = []  # Inter-arrival times
        
        # Direction tracking
        self.forward_packets = 0
        self.backward_packets = 0
        self.forward_bytes = 0
        self.backward_bytes = 0
        
        # TCP flags
        self.flags_set = set()
        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.urg_count = 0
        
        # Port info
        self.unique_src_ports = set()
        self.unique_dst_ports = set()
        
        # Status
        self.status = "active"
        self.completed_at = None
    
    def _generate_flow_id(self) -> str:
        """Generate unique flow ID"""
        ips = tuple(sorted([self.src_ip, self.dst_ip]))
        ports = tuple(sorted([self.src_port, self.dst_port]))
        key = f"{ips[0]}{ips[1]}{ports[0]}{ports[1]}{self.protocol}"
        return hashlib.md5(key.encode()).hexdigest()[:12]
    
    def add_packet(self, packet_data: Dict):
        """Add packet to flow"""
        
        now = datetime.now()
        
        # Calculate inter-arrival time
        if self.packets:
            iat = (now - self.last_packet_time).total_seconds() * 1000  # ms
            self.iat_list.append(iat)
        
        self.last_packet_time = now
        
        # Update counts
        self.packet_count += 1
        self.byte_count += packet_data.get("length", 0)
        
        # Track direction
        is_forward = (
            packet_data.get("src_ip") == self.src_ip and
            packet_data.get("dst_ip") == self.dst_ip
        )
        
        if is_forward:
            self.forward_packets += 1
            self.forward_bytes += packet_data.get("length", 0)
        else:
            self.backward_packets += 1
            self.backward_bytes += packet_data.get("length", 0)
        
        # Track flags
        if packet_data.get("flags"):
            flags = packet_data["flags"]
            if "S" in flags:
                self.syn_count += 1
            if "A" in flags:
                self.ack_count += 1
            if "F" in flags:
                self.fin_count += 1
            if "R" in flags:
                self.rst_count += 1
            if "P" in flags:
                self.psh_count += 1
            if "U" in flags:
                self.urg_count += 1
            
            self.flags_set.add(flags)
        
        # Track unique ports
        if packet_data.get("src_port"):
            self.unique_src_ports.add(packet_data["src_port"])
        if packet_data.get("dst_port"):
            self.unique_dst_ports.add(packet_data["dst_port"])
        
        # Add to list
        self.packets.append(packet_data)
    
    def get_duration(self) -> float:
        """Get flow duration in seconds"""
        return (self.last_packet_time - self.start_time).total_seconds()
    
    def is_active(self, timeout_sec: int = 30) -> bool:
        """Check if flow is still active"""
        elapsed = (datetime.now() - self.last_packet_time).total_seconds()
        
        # Flow ends on FIN flag
        if self.fin_count > 0:
            return False
        
        # Flow ends on timeout
        if elapsed > timeout_sec:
            return False
        
        return True
    
    def mark_completed(self):
        """Mark flow as completed"""
        self.status = "completed"
        self.completed_at = datetime.now()
    
    def to_dict(self) -> Dict:
        """Convert flow to dictionary"""
        duration = self.get_duration()
        
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time.isoformat(),
            "end_time": self.last_packet_time.isoformat(),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "duration": duration,
            "status": self.status,
            "forward_packets": self.forward_packets,
            "backward_packets": self.backward_packets,
            "forward_bytes": self.forward_bytes,
            "backward_bytes": self.backward_bytes,
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "psh_count": self.psh_count,
            "urg_count": self.urg_count,
            "unique_src_ports": len(self.unique_src_ports),
            "unique_dst_ports": len(self.unique_dst_ports),
            "iat_count": len(self.iat_list),
            "direction": "forward" if self.packet_count > 0 else "unknown"
        }


class FlowBuilder:
    """Builds and manages network flows"""
    
    def __init__(self, flow_timeout: int = 30, idle_timeout: int = 15):
        self.flows: Dict[str, NetworkFlow] = {}
        self.flow_timeout = flow_timeout
        self.idle_timeout = idle_timeout
        self.lock = threading.Lock()
        
        self.stats = {
            "flows_created": 0,
            "flows_completed": 0,
            "packets_processed": 0
        }
    
    def add_packet(self, packet_data: Dict) -> Tuple[str, NetworkFlow]:
        """
        Add packet to flow
        Returns: (flow_id, flow_object)
        """
        
        with self.lock:
            flow_key = self._get_flow_key(packet_data)
            
            # Create new flow if doesn't exist
            if flow_key not in self.flows:
                flow = NetworkFlow(
                    packet_data["src_ip"],
                    packet_data["dst_ip"],
                    packet_data.get("src_port", 0),
                    packet_data.get("dst_port", 0),
                    packet_data["protocol"]
                )
                self.flows[flow_key] = flow
                self.stats["flows_created"] += 1
            
            # Add packet to flow
            flow = self.flows[flow_key]
            flow.add_packet(packet_data)
            self.stats["packets_processed"] += 1
            
            return flow.flow_id, flow
    
    def _get_flow_key(self, packet_data: Dict) -> str:
        """Create bidirectional flow key"""
        
        src_ip = packet_data.get("src_ip", "0.0.0.0")
        dst_ip = packet_data.get("dst_ip", "0.0.0.0")
        src_port = packet_data.get("src_port", 0)
        dst_port = packet_data.get("dst_port", 0)
        protocol = packet_data.get("protocol", "OTHER")
        
        # Bidirectional key
        ips = tuple(sorted([src_ip, dst_ip]))
        ports = tuple(sorted([src_port, dst_port]))
        
        key = f"{ips[0]}:{ips[1]}:{ports[0]}:{ports[1]}:{protocol}"
        return key
    
    def get_completed_flows(self) -> List[NetworkFlow]:
        """Get flows that have completed"""
        
        with self.lock:
            completed = []
            to_remove = []
            
            now = datetime.now()
            
            for flow_key, flow in self.flows.items():
                # Check if flow is no longer active
                if not flow.is_active(self.flow_timeout):
                    flow.mark_completed()
                    completed.append(flow)
                    to_remove.append(flow_key)
                    self.stats["flows_completed"] += 1
            
            # Remove completed flows
            for key in to_remove:
                del self.flows[key]
            
            return completed
    
    def get_active_flows(self) -> Dict[str, Dict]:
        """Get currently active flows as dictionaries"""
        
        with self.lock:
            return {
                flow_id: flow.to_dict()
                for flow_id, flow in self.flows.items()
            }
    
    def get_flow_stats(self) -> Dict:
        """Get builder statistics"""
        
        with self.lock:
            return {
                **self.stats,
                "flows_current": len(self.flows)
            }
    
    def clear_old_flows(self):
        """Manually clear old flows"""
        self.get_completed_flows()