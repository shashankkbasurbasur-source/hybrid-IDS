"""
backend/detection/ml/attack_classifier.py

Multi-class attack classifier
Maps NIDS anomaly scores + features to specific attack types:
- Normal
- Reconnaissance / Port Scan
- Network Attack (DoS/DDoS)
- Botnet Activity
- Infiltration / Exploitation
- Web-based Attack
- Suspicious Activity
"""

import numpy as np
from typing import Tuple
from backend.core.logger import get_logger

logger = get_logger(__name__)


class AttackClassifier:
    """Rule-based attack classification based on network features."""
    
    # Attack classes
    CLASSES = {
        0: "Normal Traffic",
        1: "Reconnaissance / Port Scan",
        2: "Network Attack (DoS / Flood)",
        3: "Botnet Activity",
        4: "Infiltration",
        5: "Web-based Attack",
        6: "Suspicious Activity",
    }
    
    @staticmethod
    def classify(network_score: float, features: list) -> Tuple[int, str, float]:
        """
        Classify attack type from NIDS score and extracted features.
        
        Uses heuristic rules based on CICIDS2017 attack characteristics.
        
        Args:
            network_score: Raw anomaly score from Random Forest [0, 1]
            features: 77-dimensional feature vector
        
        Returns:
            (class_id: int, class_name: str, confidence: float)
        """
        
        try:
            # If score is very low, it's normal
            if network_score < 0.30:
                return 0, "Normal Traffic", 1.0 - network_score
            
            # Extract key features for classification
            if len(features) < 77:
                features = features + [0.0] * (77 - len(features))
            
            # Feature indices (from CICIDS)
            syn_cnt = int(features[45]) if len(features) > 45 else 0
            ack_cnt = int(features[48]) if len(features) > 48 else 0
            fin_cnt = int(features[43]) if len(features) > 43 else 0
            pkt_len_var = features[42] if len(features) > 42 else 0
            flow_duration = features[3] if len(features) > 3 else 1
            flow_pkts = features[16] if len(features) > 16 else 0
            total_pkts = features[4] + features[5] if len(features) > 5 else 1
            dst_port = int(features[0]) if len(features) > 0 else 0
            
            # ─────────────────────────────────────────────────────
            # Rule-based classification
            # ─────────────────────────────────────────────────────
            
            # PORT SCAN indicators:
            # - High SYN count relative to ACK
            # - No data transmission (low packet length variance)
            # - Many unique ports = high port entropy
            if network_score > 0.60 and syn_cnt > ack_cnt and pkt_len_var < 500:
                logger.debug("Classified as Port Scan (SYN=%d, ACK=%d)", syn_cnt, ack_cnt)
                return 1, "Reconnaissance / Port Scan", network_score
            
            # DDoS/DoS indicators:
            # - High packet rate (flow_pkts > 100)
            # - Many packets from single source (high total_pkts)
            # - No ACK responses
            # - Low variance in packet size (uniform flood pattern)
            if network_score > 0.70 and total_pkts > 100 and ack_cnt < (total_pkts * 0.1):
                logger.debug("Classified as DoS/DDoS (total_pkts=%d, ACK=%d)", total_pkts, ack_cnt)
                return 2, "Network Attack (DoS / Flood)", network_score
            
            # BOTNET indicators:
            # - Sustained high traffic rate
            # - Non-standard ports
            # - Encrypted or obfuscated patterns
            if network_score > 0.50 and flow_pkts > 1000 and dst_port not in [80, 443, 22, 21]:
                logger.debug("Classified as Botnet Activity")
                return 3, "Botnet Activity", network_score
            
            # INFILTRATION / EXPLOITATION:
            # - Score > 0.65
            # - Attempts on common service ports
            # - Data transmission (ACKs present)
            if network_score > 0.65 and ack_cnt > 0 and dst_port in [22, 21, 445, 139]:
                logger.debug("Classified as Infiltration")
                return 4, "Infiltration", network_score
            
            # WEB ATTACK indicators:
            # - Targets ports 80, 443, 8080, 8443
            # - Pattern matching not implemented (would need payload analysis)
            if network_score > 0.55 and dst_port in [80, 443, 8080, 8443]:
                logger.debug("Classified as Web-based Attack")
                return 5, "Web-based Attack", network_score
            
            # DEFAULT: Suspicious Activity
            logger.debug("Classified as Suspicious Activity (score=%.3f)", network_score)
            return 6, "Suspicious Activity", network_score
        
        except Exception as e:
            logger.error("Attack classification failed: %s", e)
            return 6, "Suspicious Activity", network_score
    
    @classmethod
    def class_name(cls, class_id: int) -> str:
        """Get attack class name from ID."""
        return cls.CLASSES.get(class_id, "Unknown")