"""
Live Packet Capture Engine with Scapy
Real network interface packet capture
"""

import threading
from datetime import datetime
from typing import Callable, Dict, Optional, List
import socket

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from backend.ingestions.interface_manager import InterfaceManager
from backend.ingestions.flow_builder import FlowBuilder
from backend.storage.nids_store import nids_db


class PacketCaptureEngine:
    """Live packet capture with flow building"""
    
    def __init__(self, interface: str = None):
        
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy required: pip install scapy")
        
        # Interface selection
        self.interface = interface or InterfaceManager.get_default_interface()
        if not self.interface:
            raise RuntimeError("No suitable network interface found")
        
        self.is_capturing = False
        self.is_paused = False
        self.capture_thread = None
        
        # Flow management
        self.flow_builder = FlowBuilder()
        
        # Statistics
        self.stats = {
            "packets_captured": 0,
            "packets_dropped": 0,
            "bytes_captured": 0,
            "errors": 0,
            "start_time": None,
            "last_update": None,
            "packets_per_sec": 0.0,
            "bytes_per_sec": 0.0
        }
        
        # Callbacks
        self.packet_callbacks: List[Callable] = []
        self.flow_callbacks: List[Callable] = []
    
    def add_packet_callback(self, callback: Callable):
        """Register packet callback"""
        self.packet_callbacks.append(callback)
    
    def add_flow_callback(self, callback: Callable):
        """Register completed flow callback"""
        self.flow_callbacks.append(callback)
    
    def start(self, packet_count: Optional[int] = None, timeout: int = None):
        """Start packet capture"""
        
        if self.is_capturing:
            return
        
        self.is_capturing = True
        self.stats["start_time"] = datetime.now()
        self.stats["packets_captured"] = 0
        self.stats["bytes_captured"] = 0
        
        print(f"[NIDS] Starting packet capture on {self.interface}")
        
        self.capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(packet_count, timeout),
            daemon=True
        )
        self.capture_thread.start()
    
    def stop(self):
        """Stop packet capture"""
        self.is_capturing = False
        
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        
        # Get any remaining completed flows
        self._process_completed_flows()
        
        print("[NIDS] Packet capture stopped")
    
    def pause(self):
        """Pause capture"""
        self.is_paused = True
    
    def resume(self):
        """Resume capture"""
        self.is_paused = False
    
    def _capture_loop(self, packet_count: Optional[int], timeout: int):
        """Main capture loop"""
        
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=False,
                count=packet_count,
                timeout=timeout
            )
        
        except PermissionError:
            print(f"[NIDS ERROR] Root required to capture on {self.interface}")
            self.stats["errors"] += 1
        except Exception as e:
            print(f"[NIDS ERROR] Capture error: {e}")
            self.stats["errors"] += 1
        finally:
            self.is_capturing = False
    
    def _packet_handler(self, packet):
        """Handle captured packet"""
        
        if not self.is_capturing or self.is_paused:
            return
        
        try:
            packet_data = self._parse_packet(packet)
            
            if not packet_data:
                return
            
            # Update stats
            self.stats["packets_captured"] += 1
            self.stats["bytes_captured"] += packet_data.get("length", 0)
            self.stats["last_update"] = datetime.now()
            
            # Store packet in database
            packet_data["flow_id"] = None  # Will be set by flow builder
            nids_db.insert_packet(packet_data)
            
            # Add to flow
            flow_id, flow = self.flow_builder.add_packet(packet_data)
            packet_data["flow_id"] = flow_id
            
            # Call packet callbacks
            for callback in self.packet_callbacks:
                try:
                    callback(packet_data)
                except:
                    pass
            
            # Check for completed flows periodically
            if self.stats["packets_captured"] % 100 == 0:
                self._process_completed_flows()
        
        except Exception as e:
            print(f"[NIDS] Packet error: {e}")
            self.stats["errors"] += 1
    
    def _parse_packet(self, packet) -> Optional[Dict]:
        """Parse captured packet to dictionary"""
        
        try:
            packet_data = {
                "timestamp": datetime.now().isoformat(),
                "src_ip": "0.0.0.0",
                "dst_ip": "0.0.0.0",
                "src_port": 0,
                "dst_port": 0,
                "protocol": "OTHER",
                "length": len(packet),
                "ttl": 0,
                "flags": None,
                "window_size": 0
            }
            
            # Parse IP layer
            if IP in packet:
                packet_data["src_ip"] = packet[IP].src
                packet_data["dst_ip"] = packet[IP].dst
                packet_data["ttl"] = packet[IP].ttl
            
            # Parse TCP layer
            if TCP in packet:
                packet_data["protocol"] = "TCP"
                packet_data["src_port"] = packet[TCP].sport
                packet_data["dst_port"] = packet[TCP].dport
                packet_data["window_size"] = packet[TCP].window
                
                # Parse TCP flags
                flags = []
                if packet[TCP].flags.F:
                    flags.append("F")
                if packet[TCP].flags.S:
                    flags.append("S")
                if packet[TCP].flags.R:
                    flags.append("R")
                if packet[TCP].flags.P:
                    flags.append("P")
                if packet[TCP].flags.A:
                    flags.append("A")
                if packet[TCP].flags.U:
                    flags.append("U")
                
                packet_data["flags"] = "".join(flags) if flags else None
            
            # Parse UDP layer
            elif UDP in packet:
                packet_data["protocol"] = "UDP"
                packet_data["src_port"] = packet[UDP].sport
                packet_data["dst_port"] = packet[UDP].dport
            
            # Parse ICMP layer
            elif ICMP in packet:
                packet_data["protocol"] = "ICMP"
            
            # Parse ARP layer
            elif ARP in packet:
                packet_data["protocol"] = "ARP"
            
            return packet_data
        
        except Exception as e:
            print(f"[NIDS] Parse error: {e}")
            return None
    
    def _process_completed_flows(self):
        """Process and store completed flows"""
        
        completed = self.flow_builder.get_completed_flows()
        
        for flow in completed:
            try:
                # Store flow in database
                nids_db.insert_flow(flow.to_dict())
                
                # Call flow callbacks
                for callback in self.flow_callbacks:
                    try:
                        callback(flow)
                    except:
                        pass
            
            except Exception as e:
                print(f"[NIDS] Flow storage error: {e}")
    
    def get_stats(self) -> Dict:
        """Get capture statistics"""
        
        if self.stats["start_time"]:
            elapsed = (datetime.now() - self.stats["start_time"]).total_seconds()
            if elapsed > 0:
                self.stats["packets_per_sec"] = self.stats["packets_captured"] / elapsed
                self.stats["bytes_per_sec"] = self.stats["bytes_captured"] / elapsed
        
        return {
            **self.stats,
            "interface": self.interface,
            "is_capturing": self.is_capturing,
            "active_flows": self.flow_builder.get_flow_stats(),
            "flows_data": self.flow_builder.get_active_flows()
        }