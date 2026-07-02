"""
MITRE ATT&CK Mapping
Central threat intelligence mapping
"""

from typing import Dict, List


class MitreMapper:
    """Maps attacks to MITRE ATT&CK techniques"""
    
    ATTACK_MITRE_MAP = {
        "Port Scan": {
            "techniques": ["T1046"],
            "tactic": "Reconnaissance",
            "name": "Network Service Discovery",
            "description": "Adversaries scan for network services to discover potential access points"
        },
        "DoS": {
            "techniques": ["T1498"],
            "tactic": "Impact",
            "name": "Network Denial of Service",
            "description": "Adversaries perform network denial of service attacks"
        },
        "DDoS": {
            "techniques": ["T1498"],
            "tactic": "Impact",
            "name": "Distributed Denial of Service",
            "description": "Large-scale network denial of service attacks"
        },
        "SSH Brute Force": {
            "techniques": ["T1110", "T1021"],
            "tactic": "Credential Access / Lateral Movement",
            "name": "Brute Force & SSH Access",
            "description": "Repeated SSH login attempts to guess credentials"
        },
        "Credential Stuffing": {
            "techniques": ["T1110", "T1091"],
            "tactic": "Credential Access",
            "name": "Credential Access",
            "description": "Testing previously compromised credentials"
        },
        "Unauthorized Access": {
            "techniques": ["T1190", "T1133"],
            "tactic": "Initial Access",
            "name": "Unauthorized Access",
            "description": "Successful unauthorized system access"
        },
        "Privilege Escalation": {
            "techniques": ["T1548", "T1134"],
            "tactic": "Privilege Escalation",
            "name": "Abuse Elevation Control Mechanism",
            "description": "Attempts to gain elevated system privileges"
        },
        "Lateral Movement": {
            "techniques": ["T1570", "T1570"],
            "tactic": "Lateral Movement",
            "name": "Lateral Tool Transfer",
            "description": "Movement within network after initial compromise"
        },
        "Data Exfiltration": {
            "techniques": ["T1041", "T1020"],
            "tactic": "Exfiltration",
            "name": "Exfiltration Over C2 Channel",
            "description": "Unauthorized data exfiltration"
        },
        "Reconnaissance": {
            "techniques": ["T1592", "T1598"],
            "tactic": "Reconnaissance",
            "name": "Gather Victim Information",
            "description": "Information gathering on potential targets"
        }
    }
    
    def get_mitre_info(self, attack_type: str) -> Dict:
        """Get MITRE mapping for attack type"""
        
        return self.ATTACK_MITRE_MAP.get(
            attack_type,
            {
                "techniques": [],
                "tactic": "Unknown",
                "name": "Unknown Attack",
                "description": "Attack type not in MITRE mapping"
            }
        )
    
    def get_techniques(self, attack_type: str) -> List[str]:
        """Get MITRE techniques for attack"""
        return self.ATTACK_MITRE_MAP.get(attack_type, {}).get("techniques", [])
    
    def get_tactic(self, attack_type: str) -> str:
        """Get MITRE tactic for attack"""
        return self.ATTACK_MITRE_MAP.get(attack_type, {}).get("tactic", "Unknown")
    
    def map_incident(self, incident: Dict) -> Dict:
        """Map incident to MITRE framework"""
        
        attack_type = incident.get("attack_type", "Unknown")
        mitre_info = self.get_mitre_info(attack_type)
        
        return {
            "attack_type": attack_type,
            "techniques": mitre_info.get("techniques", []),
            "tactic": mitre_info.get("tactic", "Unknown"),
            "technique_name": mitre_info.get("name", "Unknown"),
            "description": mitre_info.get("description", ""),
            "attack_category": incident.get("attack_category", "Unknown")
        }