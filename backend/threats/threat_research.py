"""
backend/threats/threat_research.py

Threat intelligence and analysis engine.
Takes an alert and provides:
 - MITRE ATT&CK framework mapping
 - Attack description & behavior
 - Indicators of compromise (IOCs)
 - Recommended mitigation
 - Similar attacks / TTPs
"""

from typing import Optional, Dict, List

# MITRE ATT&CK Techniques Database
MITRE_DB = {
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Automated attempts to compromise user accounts by testing combinations of usernames and passwords.",
        "behavior": "Multiple failed authentication attempts from single source IP",
        "iocs": ["Multiple auth failures (>5)", "Same source IP multiple attempts", "Dictionary words as usernames"],
        "mitigation": [
            "Implement account lockout after failed attempts",
            "Enable MFA/2FA",
            "Monitor failed login rates",
            "Use strong password policy",
            "Deploy WAF/IDS rules"
        ],
        "similar_attacks": ["T1021 - Remote Services", "T1589 - Gather Victim Identity Information"]
    },
    "T1046": {
        "name": "Network Service Scanning",
        "tactic": "Reconnaissance",
        "description": "Attacker probes a network to determine active hosts and open ports.",
        "behavior": "Sequential connections to multiple ports, SYN scans, rapid port enumeration",
        "iocs": ["Sequential dst ports", "SYN packets without data", "High port diversity", "Short lived connections"],
        "mitigation": [
            "Deploy network segmentation",
            "Use rate limiting on port responses",
            "Monitor for scanning patterns",
            "Deploy IDS with port scan detection",
            "Block ICMP if not needed"
        ],
        "similar_attacks": ["T1518 - Software Discovery", "T1526 - Cloud Service Discovery"]
    },
    "T1498": {
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Attacker floods network with traffic to exhaust resources or prevent legitimate access.",
        "behavior": "High packet rate, large byte volumes, SYN floods, UDP floods, ICMP floods",
        "iocs": ["Packet rate >1000/sec", "Single source to single dest", "All packets same size", "Spoofed IPs"],
        "mitigation": [
            "Deploy DDoS protection service",
            "Implement rate limiting",
            "Use SYN cookies",
            "Configure firewall rules",
            "Increase bandwidth capacity"
        ],
        "similar_attacks": ["T1499 - Network Denial of Service (Application Layer)", "T1561 - Disk Wipe"]
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Attacker uses remote services like SSH, RDP, Telnet to move laterally or gain initial access.",
        "behavior": "Connections to SSH (22), RDP (3389), Telnet (23) from suspicious IPs",
        "iocs": ["Connection to ssh/rdp from external IP", "Multiple logon attempts", "Admin account usage"],
        "mitigation": [
            "Restrict remote access (VPN only)",
            "Disable unnecessary services",
            "Change default ports",
            "Implement jump host/bastion",
            "Monitor remote service logs"
        ],
        "similar_attacks": ["T1078 - Valid Accounts", "T1570 - Lateral Tool Transfer"]
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control / Exfiltration",
        "description": "Attacker uses legitimate application-layer protocols to hide malicious traffic.",
        "behavior": "HTTP/HTTPS with unusual patterns, DNS tunneling, DNS queries with encoded data",
        "iocs": ["HTTP POST with large body", "DNS with long queries", "HTTP User-Agent anomalies"],
        "mitigation": [
            "Monitor protocol usage",
            "Implement DLP (Data Loss Prevention)",
            "Analyze SSL/TLS certificates",
            "Monitor DNS for tunneling",
            "Use intrusion detection for patterns"
        ],
        "similar_attacks": ["T1048 - Exfiltration Over Alternative Protocol", "T1071 - Application Layer Protocol (variants)"]
    }
}

# Attack Scenarios Database
ATTACK_SCENARIOS = {
    "Brute Force / Unauthorized Access": {
        "mnemonic": "BF",
        "risk_level": "HIGH",
        "description": "Attacker attempts unauthorized access through credential guessing",
        "detection_method": "HIDS - SSH auth log analysis",
        "phase": "Initial Access / Credential Access",
        "indicators": [
            "Multiple failed login attempts",
            "Common username patterns (root, admin, test)",
            "Failed then successful attempt from same IP",
            "Rapid auth attempts (>5/min)",
        ],
        "response": "Block source IP, enable MFA, review successful logins"
    },
    "Reconnaissance / Port Scan": {
        "mnemonic": "PS",
        "risk_level": "MEDIUM",
        "description": "Attacker probes for open ports and services",
        "detection_method": "NIDS - Sequential dst port connections",
        "phase": "Reconnaissance",
        "indicators": [
            "Sequential destination ports",
            "High port diversity (>50 unique ports)",
            "SYN packets without data exchange",
            "Low byte count per connection"
        ],
        "response": "Enable IDS rules, restrict inbound, analyze for follow-up attacks"
    },
    "Network Attack (DoS / Flood)": {
        "mnemonic": "DOS",
        "risk_level": "CRITICAL",
        "description": "Attacker floods network with traffic to exhaust resources",
        "detection_method": "NIDS - Abnormal traffic rate/volume",
        "phase": "Impact",
        "indicators": [
            "Packet rate spike (>1000 pkt/sec)",
            "Byte volume spike (>1MB/sec from single src)",
            "Single source targeting single destination",
            "Same packet size repeated"
        ],
        "response": "Activate DDoS mitigation, rate limiting, notify upstream provider"
    },
    "Multi-Stage Hybrid Attack": {
        "mnemonic": "HYBRID",
        "risk_level": "CRITICAL",
        "description": "Coordinated network + host-based attack (reconnaissance then exploitation)",
        "detection_method": "Fusion Engine - both NIDS + HIDS signals",
        "phase": "Multiple (Recon -> Initial Access -> Lateral Movement)",
        "indicators": [
            "Port scanning followed by auth attempts",
            "Unusual network traffic + auth failures",
            "Internal host-to-host connections after external scan",
            "Privilege escalation attempt post-access"
        ],
        "response": "Full incident response: isolate host, capture logs, forensics, credential reset"
    },
    "Suspicious Activity": {
        "mnemonic": "SUSP",
        "risk_level": "MEDIUM",
        "description": "Unclassified anomalous behavior detected",
        "detection_method": "ML model anomaly score",
        "phase": "Unclear - investigate",
        "indicators": ["Anomaly score > threshold", "Unusual feature combination"],
        "response": "Investigate logs, correlate with other alerts, escalate if needed"
    }
}


def get_threat_analysis(attack_type: str, attack_domain: str, 
                        network_score: float, host_score: float,
                        src_ip: Optional[str] = None) -> Dict:
    """
    Returns detailed threat analysis for an alert.
    """
    scenario = ATTACK_SCENARIOS.get(attack_type, ATTACK_SCENARIOS["Suspicious Activity"])
    mitre = MITRE_DB.get(scenario.get("mitre_tactic", ""), {})

    return {
        "scenario": scenario,
        "mitre": mitre,
        "risk_level": scenario["risk_level"],
        "confidence": (network_score + host_score) / 2,
        "affected_domain": attack_domain,
        "source_ip": src_ip or "unknown",
        "indicators": scenario["indicators"],
        "mitigation_steps": mitre.get("mitigation", []) or scenario["response"].split(", "),
        "similar_attacks": mitre.get("similar_attacks", []),
        "phase": scenario["phase"],
    }


def get_attack_iocs(attack_type: str) -> List[str]:
    """Returns Indicators of Compromise for an attack type."""
    scenario = ATTACK_SCENARIOS.get(attack_type, {})
    return scenario.get("indicators", [])


def get_mitre_info(attack_type: str) -> Optional[Dict]:
    """Returns MITRE ATT&CK info for an attack type."""
    for tactic, info in MITRE_DB.items():
        if attack_type.lower() in info["name"].lower():
            return {**info, "tactic_id": tactic}
    return None