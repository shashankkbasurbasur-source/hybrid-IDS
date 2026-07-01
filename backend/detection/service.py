"""
Hybrid Detection Service - Orchestrates NIDS, HIDS, and Fusion
"""

from typing import Dict, List, Tuple
from backend.detection.ml.network_model import predict_network
from backend.detection.ml.host_model import predict_host
from backend.detection.fusion import hybrid_fusion
from backend.alerts.alert_builder import build_alert, enrich_alert_with_threat_intel


class AttackClassifier:
    """Classify attack types from scores"""
    
    @staticmethod
    def classify_network_attack(score: float, features: Dict) -> Tuple[str, str]:
        """Classify network attack type"""
        
        if score < 0.5:
            return "Normal", "Normal"
        
        # Port scanning detection
        unique_dports = features.get("unique_dports", 0)
        if unique_dports > 10 or features.get("port_diversity", 0) > 0.7:
            return "Port Scan", "Network"
        
        # DoS/DDoS detection
        packet_rate = features.get("packet_rate", 0)
        if packet_rate > 1000:
            return "DoS / DDoS", "Network"
        
        # Generic network attack
        if score > 0.75:
            return "Network Attack", "Network"
        
        return "Suspicious Network Activity", "Network"
    
    @staticmethod
    def classify_host_attack(score: float, features: Dict) -> Tuple[str, str]:
        """Classify host attack type"""
        
        if score < 0.6:
            return "Normal", "Normal"
        
        # Brute force detection
        failed_logins = features.get("fail_count", 0)
        if failed_logins > 5:
            return "Brute Force", "Host"
        
        # Success after multiple failures
        if features.get("success_after_fail", 0):
            return "Brute Force", "Host"
        
        # Process anomaly
        if features.get("anomaly_score", 0) > 0.8:
            return "Anomalous System Activity", "Host"
        
        return "Suspicious Host Activity", "Host"


def run_hybrid_detection(
    network_features: List[float],
    host_features: List[float],
    network_context: Dict = None,
    host_context: Dict = None
) -> Dict:
    """
    Main hybrid detection pipeline
    
    Args:
        network_features: NIDS feature vector
        host_features: HIDS feature vector
        network_context: Additional network metadata
        host_context: Additional host metadata
    
    Returns:
        Complete detection result with alerts and analysis
    """
    
    network_context = network_context or {}
    host_context = host_context or {}
    
    # --- Step 1: Individual Model Predictions ---
    network_score = predict_network(network_features)
    host_score = predict_host(host_features)
    
    # --- Step 2: Attack Classification ---
    network_attack, network_domain = AttackClassifier.classify_network_attack(
        network_score,
        network_context
    )
    
    host_attack, host_domain = AttackClassifier.classify_host_attack(
        host_score,
        host_context
    )
    
    # --- Step 3: Hybrid Fusion ---
    fusion_result = hybrid_fusion(network_score, host_score)
    
    # Determine final attack type based on fusion
    if fusion_result["decision"] == "Intrusion":
        if network_score > host_score:
            final_attack_type = network_attack
            final_domain = "Network"
        elif host_score > network_score:
            final_attack_type = host_attack
            final_domain = "Host"
        else:
            final_attack_type = "Hybrid Attack"
            final_domain = "Hybrid"
    else:
        final_attack_type = "Normal"
        final_domain = "None"
    
    # --- Step 4: Alert Generation ---
    alert = build_alert(
        decision=fusion_result["decision"],
        score=fusion_result["final_score"],
        attack_type=final_attack_type,
        domain=final_domain,
        source_ip=network_context.get("source_ip", "Unknown"),
        destination_ip=network_context.get("destination_ip", "Unknown"),
        severity_override=fusion_result.get("severity")
    )
    
    # --- Step 5: Threat Intelligence Enrichment ---
    alert = enrich_alert_with_threat_intel(alert)
    
    # --- Step 6: Final Response ---
    return {
        # Individual scores
        "network_score": round(network_score, 4),
        "host_score": round(host_score, 4),
        
        # Fusion results
        "final_score": fusion_result["final_score"],
        "decision": fusion_result["decision"],
        
        # Attack information
        "attack_type": final_attack_type,
        "attack_domain": final_domain,
        "location": fusion_result.get("location", "None"),
        
        # Severity and reasoning
        "severity": fusion_result.get("severity", "LOW"),
        "reason": fusion_result.get("reason", ["No anomaly detected"]),
        "confidence": round(fusion_result["final_score"], 4),
        
        # Structured alert
        "alert": alert,
        
        # Threat intelligence
        "threat_intelligence": alert.get("threat_intelligence", {}),
        
        # Triggered components
        "triggered_by": fusion_result.get("triggered_by", []),
    }