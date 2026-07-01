"""
Flow-based Network Feature Extraction for NIDS
"""

import numpy as np
from typing import List, Dict


class NetworkFlowFeatureExtractor:
    """Extracts features from network flows for ML detection"""
    
    FEATURE_SIZE = 78
    
    def __init__(self):
        self.port_knowledge = self._load_port_knowledge()
    
    def _load_port_knowledge(self) -> Dict:
        """Well-known ports and their categories"""
        return {
            "well_known": list(range(0, 1024)),
            "registered": list(range(1024, 49152)),
            "ephemeral": list(range(49152, 65536)),
            "dns": [53],
            "http": [80, 8080],
            "https": [443, 8443],
            "ssh": [22],
            "telnet": [23],
            "smtp": [25, 587],
            "pop3": [110],
            "imap": [143],
            "ntp": [123],
            "snmp": [161]
        }
    
    def extract_from_flow(self, flow: Dict) -> List[float]:
        """Extract features from a single flow"""
        
        features = [0.0] * self.FEATURE_SIZE
        
        # --- Basic Flow Statistics ---
        features[0] = float(flow.get("packet_count", 0))
        features[1] = float(flow.get("byte_count", 0))
        features[2] = float(flow.get("duration", 0.001))
        
        # Byte and packet rates
        duration = flow.get("duration", 0.001)
        features[3] = flow.get("byte_count", 0) / duration if duration > 0 else 0
        features[4] = flow.get("packet_count", 0) / duration if duration > 0 else 0
        
        # --- Protocol Analysis ---
        protocol = flow.get("protocol", "OTHER")
        if protocol == "TCP":
            features[5] = 1.0
        elif protocol == "UDP":
            features[6] = 1.0
        elif protocol == "ICMP":
            features[7] = 1.0
        else:
            features[8] = 1.0
        
        # --- Port Analysis ---
        src_port = flow.get("src_port", 0)
        dst_port = flow.get("dst_port", 0)
        
        features[9] = float(src_port)
        features[10] = float(dst_port)
        
        # Port categories
        if dst_port in self.port_knowledge["well_known"]:
            features[11] = 1.0
        elif dst_port in self.port_knowledge["registered"]:
            features[12] = 1.0
        else:
            features[13] = 1.0
        
        # Known service ports
        if dst_port in self.port_knowledge["ssh"]:
            features[14] = 1.0
        elif dst_port in self.port_knowledge["http"] + self.port_knowledge["https"]:
            features[15] = 1.0
        elif dst_port in self.port_knowledge["dns"]:
            features[16] = 1.0
        
        # --- Multi-flow Scanning Detection ---
        features[17] = float(flow.get("unique_dports", 0))  # Scan detector
        features[18] = float(flow.get("unique_sports", 0))
        
        # --- Flow Directionality ---
        features[19] = 1.0 if flow.get("packet_count", 0) > 0 else 0
        
        # Average packet size
        packet_count = flow.get("packet_count", 1)
        avg_packet_size = flow.get("byte_count", 0) / packet_count if packet_count > 0 else 0
        features[20] = avg_packet_size
        
        # --- Suspicious Patterns ---
        # High port number destination (unusual)
        if dst_port > 10000:
            features[21] = 1.0
        
        # Low packet count but high bytes (potential command injection)
        if packet_count < 5 and flow.get("byte_count", 0) > 1000:
            features[22] = 1.0
        
        # Very short duration high traffic (burst)
        if duration < 1.0 and flow.get("packet_count", 0) > 100:
            features[23] = 1.0
        
        # TCP flags (if present)
        flags = flow.get("flags", [])
        if flags:
            features[24] = len(flags) / 10.0  # Normalized flag diversity
        
        # Padding for model compatibility
        return features[:self.FEATURE_SIZE]
    
    def extract_from_packets(self, packets: List[Dict]) -> List[float]:
        """Extract features from raw packet list (fallback)"""
        
        if not packets:
            return [0.0] * self.FEATURE_SIZE
        
        features = [0.0] * self.FEATURE_SIZE
        
        # Basic stats
        features[0] = float(len(packets))
        features[1] = sum(p.get("length", 0) for p in packets)
        features[2] = max([p.get("length", 0) for p in packets]) if packets else 0
        features[3] = min([p.get("length", 0) for p in packets]) if packets else 0
        
        # Protocol distribution
        tcp_count = sum(1 for p in packets if p.get("protocol") == "TCP")
        udp_count = sum(1 for p in packets if p.get("protocol") == "UDP")
        
        features[5] = float(tcp_count)
        features[6] = float(udp_count)
        features[7] = tcp_count / len(packets) if packets else 0
        
        # Port analysis
        src_ports = [p.get("src_port", 0) for p in packets if p.get("src_port", 0) > 0]
        dst_ports = [p.get("dst_port", 0) for p in packets if p.get("dst_port", 0) > 0]
        
        features[9] = len(set(src_ports))
        features[10] = len(set(dst_ports))
        
        # High ports count (scanning indicator)
        high_ports = sum(1 for p in dst_ports if p > 1024)
        features[11] = float(high_ports)
        
        return features[:self.FEATURE_SIZE]