"""
Flow-based Feature Extraction for CICIDS2017
Extracts 77-80 features used in model training
"""

import numpy as np
from typing import Dict, List
import math


class FlowFeatureExtractor:
    """Extracts features from completed flows"""
    
    # Feature names matching CICIDS2017
    FEATURE_NAMES = [
        'Flow Duration', 'Total Fwd Packets', 'Total Bwd Packets',
        'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
        'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
        'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
        'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s',
        'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
        'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std',
        'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
        'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
        'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
        'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length',
        'Max Packet Length', 'Packet Length Mean', 'Packet Length Std',
        'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count',
        'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
        'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size',
        'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length',
        'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
        'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
        'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
        'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
        'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean',
        'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std',
        'Idle Max', 'Idle Min'
    ]
    
    FEATURE_SIZE = 77  # Standard for CICIDS2017
    
    def extract(self, flow: Dict) -> List[float]:
        """Extract features from a flow"""
        
        features = [0.0] * self.FEATURE_SIZE
        
        try:
            # Duration in seconds
            duration = float(flow.get("duration", 0.001))
            if duration <= 0:
                duration = 0.001
            
            fwd_packets = float(flow.get("forward_packets", 0))
            bwd_packets = float(flow.get("backward_packets", 0))
            total_packets = fwd_packets + bwd_packets
            
            fwd_bytes = float(flow.get("forward_bytes", 0))
            bwd_bytes = float(flow.get("backward_bytes", 0))
            total_bytes = fwd_bytes + bwd_bytes
            
            # Basic flow statistics
            features[0] = duration * 1000  # Convert to milliseconds
            features[1] = fwd_packets
            features[2] = bwd_packets
            features[3] = fwd_bytes
            features[4] = bwd_bytes
            
            # Packet length statistics (simplified)
            if fwd_packets > 0:
                fwd_avg_length = fwd_bytes / fwd_packets
                features[5] = fwd_avg_length  # Max (simplified)
                features[6] = fwd_avg_length  # Min (simplified)
                features[7] = fwd_avg_length  # Mean
                features[8] = 0.0  # Std (simplified)
            
            if bwd_packets > 0:
                bwd_avg_length = bwd_bytes / bwd_packets
                features[9] = bwd_avg_length  # Max
                features[10] = bwd_avg_length  # Min
                features[11] = bwd_avg_length  # Mean
                features[12] = 0.0  # Std
            
            # Flow rates
            if duration > 0:
                features[13] = total_bytes / duration  # Bytes/sec
                features[14] = total_packets / duration  # Packets/sec
            
            # IAT (Inter-arrival time) statistics
            iat_count = float(flow.get("iat_count", 0))
            if iat_count > 0:
                features[15] = 0.0  # Mean (would need actual values)
                features[16] = 0.0  # Std
                features[17] = 0.0  # Max
                features[18] = 0.0  # Min
            
            # Protocol-specific flags
            syn_count = float(flow.get("syn_count", 0))
            ack_count = float(flow.get("ack_count", 0))
            fin_count = float(flow.get("fin_count", 0))
            rst_count = float(flow.get("rst_count", 0))
            psh_count = float(flow.get("psh_count", 0))
            urg_count = float(flow.get("urg_count", 0))
            
            # Flag counts (positions in feature vector)
            features[29] = 0.0  # Fwd PSH
            features[30] = psh_count  # Bwd PSH
            features[31] = 0.0  # Fwd URG
            features[32] = urg_count  # Bwd URG
            features[39] = fin_count
            features[40] = syn_count
            features[41] = rst_count
            features[42] = psh_count
            features[43] = ack_count
            features[44] = urg_count
            
            # Unique ports
            unique_dst_ports = float(flow.get("unique_dst_ports", 0))
            
            # Scanning detection
            if unique_dst_ports > 5:
                features[50] = unique_dst_ports
            
            # Average packet size
            if total_packets > 0:
                features[52] = total_bytes / total_packets
            
            # Protocol flags
            protocol = flow.get("protocol", "OTHER")
            if protocol == "TCP":
                features[60] = 1.0
            elif protocol == "UDP":
                features[61] = 1.0
            else:
                features[62] = 1.0
            
            # Down/Up Ratio
            if fwd_packets > 0:
                features[48] = bwd_packets / fwd_packets
            
            # Duration indicators
            if duration < 1.0:
                features[65] = 1.0  # Short burst
            
            # Ensure no NaN or Inf
            features = [0.0 if (math.isnan(f) or math.isinf(f)) else f 
                       for f in features]
            
            # Validate feature count
            if len(features) < self.FEATURE_SIZE:
                features.extend([0.0] * (self.FEATURE_SIZE - len(features)))
            
            return features[:self.FEATURE_SIZE]
        
        except Exception as e:
            print(f"Feature extraction error: {e}")
            return [0.0] * self.FEATURE_SIZE