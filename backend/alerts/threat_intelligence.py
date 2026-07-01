"""
Threat Intelligence Knowledge Base and Analysis
"""

from typing import Dict, List, Optional
import json
from pathlib import Path


class ThreatIntelligenceBase:
    """Local knowledge base for threat analysis"""
    
    THREAT_KNOWLEDGE = {
        "Port Scan": {
            "mitre_technique": "T1046",
            "mitre_name": "Network Service Discovery",
            "category": "Reconnaissance",
            "description": "Adversary is scanning for open network services",
            "severity": "Medium",
            "indicators": [
                "High number of destination ports",
                "SYN packets to multiple ports",
                "High port entropy",
                "Rapid connection attempts"
            ],
            "common_tools": ["Nmap", "Masscan", "Zmap"],
            "mitigation": [
                "Enable firewall rules",
                "Rate limit incoming connections",
                "Monitor unusual scanning patterns",
                "Block known scanning tools"
            ],
            "iocs": ["Destination port diversity", "SYN flood patterns"],
            "impact": "Network reconnaissance may lead to targeted attacks"
        },
        
        "DoS / DDoS": {
            "mitre_technique": "T1498",
            "mitre_name": "Network Denial of Service",
            "category": "Impact",
            "description": "Attempt to consume network resources and disrupt availability",
            "severity": "High",
            "indicators": [
                "Unusually high packet rate",
                "Traffic spike",
                "Repeated destination IP",
                "High bandwidth usage"
            ],
            "common_tools": ["hping3", "LOIC", "Slowhttptest"],
            "mitigation": [
                "DDoS mitigation service",
                "Rate limiting",
                "Traffic filtering",
                "Upstream filtering"
            ],
            "iocs": ["Packet rate threshold", "Bandwidth surge"],
            "impact": "Service unavailability and potential financial loss"
        },
        
        "Brute Force": {
            "mitre_technique": "T1110",
            "mitre_name": "Brute Force",
            "category": "Credential Access",
            "description": "Repeated authentication attempts to gain access",
            "severity": "High",
            "indicators": [
                "Multiple failed login attempts",
                "Same source IP, multiple users",
                "Rapid authentication requests",
                "Success after failures"
            ],
            "common_tools": ["Hydra", "Medusa", "Hashcat"],
            "mitigation": [
                "Account lockout policies",
                "Rate limiting",
                "Multi-factor authentication",
                "SSH key authentication"
            ],
            "iocs": ["Failed login count", "Attempt rate", "User enumeration"],
            "impact": "Unauthorized account compromise"
        },
        
        "Privilege Escalation": {
            "mitre_technique": "T1548",
            "mitre_name": "Abuse Elevation Control Mechanism",
            "category": "Privilege Escalation",
            "description": "Attempt to gain elevated system privileges",
            "severity": "Critical",
            "indicators": [
                "sudo command execution",
                "Kernel exploitation attempts",
                "File permission changes",
                "Unusual system calls"
            ],
            "common_tools": ["GTFOBins", "Dirty COW", "DirtyCow"],
            "mitigation": [
                "Patch management",
                "Principle of least privilege",
                "Audit sudo usage",
                "Monitor kernel activities"
            ],
            "iocs": ["Unusual sudo patterns", "Kernel syscalls"],
            "impact": "Full system compromise"
        },
        
        "Lateral Movement": {
            "mitre_technique": "T1570",
            "mitre_name": "Lateral Tool Transfer",
            "category": "Lateral Movement",
            "description": "Attacker moving within network after initial compromise",
            "severity": "High",
            "indicators": [
                "Unusual inter-host communication",
                "Multiple login attempts across hosts",
                "File transfers between hosts",
                "Beacon-like traffic patterns"
            ],
            "common_tools": ["PsExec", "WMI", "PowerShell Remoting"],
            "mitigation": [
                "Network segmentation",
                "Endpoint detection",
                "Monitor lateral traffic",
                "Host-based firewalls"
            ],
            "iocs": ["Inter-host connections", "Suspicious beacon patterns"],
            "impact": "Wider network compromise"
        },
        
        "Anomalous System Activity": {
            "mitre_technique": "T1566",
            "mitre_name": "Phishing",
            "category": "Initial Access",
            "description": "Suspicious system behavior detected",
            "severity": "Medium",
            "indicators": [
                "Unusual process execution",
                "Memory anomalies",
                "File system changes",
                "Registry modifications"
            ],
            "common_tools": ["Generic malware", "Fileless attacks"],
            "mitigation": [
                "EDR solutions",
                "Process monitoring",
                "Behavior analysis",
                "Sandboxing"
            ],
            "iocs": ["Process chains", "Behavioral patterns"],
            "impact": "Potential malware execution"
        }
    }
    
    @staticmethod
    def analyze_alert(attack_type: str, confidence: float, 
                     domain: str = "Unknown") -> Dict:
        """Generate threat analysis for an alert"""
        
        if attack_type in ThreatIntelligenceBase.THREAT_KNOWLEDGE:
            threat_data = ThreatIntelligenceBase.THREAT_KNOWLEDGE[attack_type]
        else:
            threat_data = {
                "mitre_technique": "Unknown",
                "mitre_name": "Unknown Threat",
                "category": "Unknown",
                "description": f"Unclassified threat detected",
                "severity": "Low",
                "indicators": ["Unknown indicators"],
                "common_tools": ["Unknown"],
                "mitigation": ["Investigate further"],
                "iocs": ["Unknown"],
                "impact": "Requires manual investigation"
            }
        
        return {
            "attack_type": attack_type,
            "confidence": round(confidence, 3),
            "mitre_technique": threat_data["mitre_technique"],
            "mitre_name": threat_data["mitre_name"],
            "category": threat_data["category"],
            "description": threat_data["description"],
            "severity": threat_data["severity"],
            "domain": domain,
            "indicators": threat_data["indicators"],
            "common_tools": threat_data["common_tools"],
            "mitigation": threat_data["mitigation"],
            "iocs": threat_data["iocs"],
            "impact": threat_data["impact"],
            "status": "Unconfirmed" if confidence < 0.8 else "High Confidence"
        }