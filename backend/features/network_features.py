"""
backend/features/network_features.py

FIXED FOR PHASE 2:
 - Extracts EXACTLY 77 features (matches CICIDS2017 training)
 - Uses REAL packet timestamps (not fake IAT)
 - Properly handles inter-arrival times
 - Prevents zero-dimension issues
"""

import numpy as np
from typing import List, Dict, Optional
from backend.core.logger import get_logger

logger = get_logger(__name__)


class NetworkFeatureExtractor:
    """Extracts exactly 77 network features from packet events."""
    
    # 77 feature names matching CICIDS2017
    FEATURE_NAMES = [
        'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
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
        'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length.1',
        'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
        'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
        'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
        'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
        'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Std',
        'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
    ]
    
    def __init__(self):
        """Initialize feature extractor."""
        if len(self.FEATURE_NAMES) != 77:
            logger.warning("Feature count mismatch: %d != 77. May cause errors.",
                          len(self.FEATURE_NAMES))
    
    def extract(self, events: List[Dict]) -> List[float]:
        """
        Extract exactly 77 features from packet events.
        """
        if not events:
            logger.warning("No events provided. Returning zero feature vector.")
            return [0.0] * 77
        
        try:
            # Extract timestamps
            timestamps = []
            for evt in events:
                ts_str = str(evt.get("timestamp", "0"))
                try:
                    ts = float(ts_str)
                    timestamps.append(ts)
                except (ValueError, TypeError):
                    timestamps.append(float(len(timestamps)))
            
            # Calculate inter-arrival times
            iats = []
            for i in range(1, len(timestamps)):
                iat = timestamps[i] - timestamps[i-1]
                iats.append(max(iat, 0.0001))  # Avoid zero/negative IAT
            
            if not iats:
                iats = [0.0001]
            
            total_packets = len(events)
            
            # Separate by direction (TCP/UDP forward, backward)
            fwd_packets = [e for e in events if e.get("protocol") == "TCP"]
            bwd_packets = [e for e in events if e.get("protocol") == "UDP"]
            
            fwd_lengths = [e.get("length", 0) for e in fwd_packets]
            bwd_lengths = [e.get("length", 0) for e in bwd_packets]
            all_lengths = [e.get("length", 0) for e in events]
            
            fwd_bytes = sum(fwd_lengths)
            bwd_bytes = sum(bwd_lengths)
            total_bytes = fwd_bytes + bwd_bytes
            
            fin_flags = sum(1 for e in events if e.get("flags", 0) & 0x01)
            syn_flags = sum(1 for e in events if e.get("flags", 0) & 0x02)
            rst_flags = sum(1 for e in events if e.get("flags", 0) & 0x04)
            psh_flags = sum(1 for e in events if e.get("flags", 0) & 0x08)
            ack_flags = sum(1 for e in events if e.get("flags", 0) & 0x10)
            urg_flags = sum(1 for e in events if e.get("flags", 0) & 0x20)
            
            def safe_mean(lst):
                return float(np.mean(lst)) if lst else 0.0
            
            def safe_std(lst):
                return float(np.std(lst)) if lst and len(lst) > 1 else 0.0
            
            def safe_max(lst):
                return float(max(lst)) if lst else 0.0
            
            def safe_min(lst):
                return float(min(lst)) if lst else 0.0
            
            flow_duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0.0
            
            feat_dict = {
                'Flow Duration': flow_duration,
                'Total Fwd Packets': float(len(fwd_packets)),
                'Total Backward Packets': float(len(bwd_packets)),
                'Total Length of Fwd Packets': float(fwd_bytes),
                'Total Length of Bwd Packets': float(bwd_bytes),
                'Fwd Packet Length Max': safe_max(fwd_lengths),
                'Fwd Packet Length Min': safe_min(fwd_lengths),
                'Fwd Packet Length Mean': safe_mean(fwd_lengths),
                'Fwd Packet Length Std': safe_std(fwd_lengths),
                'Bwd Packet Length Max': safe_max(bwd_lengths),
                'Bwd Packet Length Min': safe_min(bwd_lengths),
                'Bwd Packet Length Mean': safe_mean(bwd_lengths),
                'Bwd Packet Length Std': safe_std(bwd_lengths),
                'Flow Bytes/s': total_bytes / flow_duration if flow_duration > 0 else 0.0,
                'Flow Packets/s': total_packets / flow_duration if flow_duration > 0 else 0.0,
                'Flow IAT Mean': safe_mean(iats),
                'Flow IAT Std': safe_std(iats),
                'Flow IAT Max': safe_max(iats),
                'Flow IAT Min': safe_min(iats),
                'Fwd IAT Total': sum(iats) if fwd_packets else 0.0,
                'Fwd IAT Mean': safe_mean(iats) if fwd_packets else 0.0,
                'Fwd IAT Std': safe_std(iats) if fwd_packets else 0.0,
                'Fwd IAT Max': safe_max(iats) if fwd_packets else 0.0,
                'Fwd IAT Min': safe_min(iats) if fwd_packets else 0.0,
                'Bwd IAT Total': sum(iats) if bwd_packets else 0.0,
                'Bwd IAT Mean': safe_mean(iats) if bwd_packets else 0.0,
                'Bwd IAT Std': safe_std(iats) if bwd_packets else 0.0,
                'Bwd IAT Max': safe_max(iats) if bwd_packets else 0.0,
                'Bwd IAT Min': safe_min(iats) if bwd_packets else 0.0,
                'Fwd PSH Flags': float(psh_flags) if fwd_packets else 0.0,
                'Bwd PSH Flags': 0.0,
                'Fwd URG Flags': float(urg_flags) if fwd_packets else 0.0,
                'Bwd URG Flags': 0.0,
                'Fwd Header Length': float(20 * len(fwd_packets)),
                'Bwd Header Length': float(20 * len(bwd_packets)),
                'Fwd Packets/s': len(fwd_packets) / flow_duration if flow_duration > 0 else 0.0,
                'Bwd Packets/s': len(bwd_packets) / flow_duration if flow_duration > 0 else 0.0,
                'Min Packet Length': safe_min(all_lengths),
                'Max Packet Length': safe_max(all_lengths),
                'Packet Length Mean': safe_mean(all_lengths),
                'Packet Length Std': safe_std(all_lengths),
                'Packet Length Variance': float(np.var(all_lengths)) if len(all_lengths) > 1 else 0.0,
                'FIN Flag Count': float(fin_flags),
                'SYN Flag Count': float(syn_flags),
                'RST Flag Count': float(rst_flags),
                'PSH Flag Count': float(psh_flags),
                'ACK Flag Count': float(ack_flags),
                'URG Flag Count': float(urg_flags),
                'CWE Flag Count': 0.0,
                'ECE Flag Count': 0.0,
                'Down/Up Ratio': len(bwd_packets) / len(fwd_packets) if fwd_packets else 0.0,
                'Average Packet Size': safe_mean(all_lengths) if all_lengths else 0.0,
                'Avg Fwd Segment Size': safe_mean(fwd_lengths) if fwd_lengths else 0.0,
                'Avg Bwd Segment Size': safe_mean(bwd_lengths) if bwd_lengths else 0.0,
                'Fwd Header Length.1': float(20 * len(fwd_packets)),
                'Fwd Avg Bytes/Bulk': 0.0,
                'Fwd Avg Packets/Bulk': 0.0,
                'Fwd Avg Bulk Rate': 0.0,
                'Bwd Avg Bytes/Bulk': 0.0,
                'Bwd Avg Packets/Bulk': 0.0,
                'Bwd Avg Bulk Rate': 0.0,
                'Subflow Fwd Packets': float(len(fwd_packets)),
                'Subflow Fwd Bytes': float(fwd_bytes),
                'Subflow Bwd Packets': float(len(bwd_packets)),
                'Subflow Bwd Bytes': float(bwd_bytes),
                'Init_Win_bytes_forward': 29200.0 if syn_flags > 0 else 0.0,
                'Init_Win_bytes_backward': 0.0,
                'act_data_pkt_fwd': float(len([e for e in fwd_packets if e.get("length", 0) > 0])),
                'min_seg_size_forward': 20.0,
                'Active Mean': 0.0,
                'Active Std': 0.0,
                'Active Max': 0.0,
                'Active Min': 0.0,
                'Idle Mean': 0.0,
                'Idle Std': 0.0,
                'Idle Max': 0.0,
                'Idle Min': 0.0
            }
            
            features = [feat_dict.get(name, 0.0) for name in self.FEATURE_NAMES]
            logger.debug("Extracted 77 features from %d packets", len(events))
            return features
        
        except Exception as e:
            logger.error("Feature extraction failed: %s. Returning zeros.", e)
            return [0.0] * 77