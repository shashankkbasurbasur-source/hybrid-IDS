"""
Threat Knowledge Database
Centralized intelligence repository for all supported attacks
"""

from typing import Dict, List, Optional
from enum import Enum


class AttackStage(Enum):
    """MITRE ATT&CK lifecycle stages"""
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class ThreatKnowledgeBase:
    """Central repository of threat intelligence"""
    
    KNOWLEDGE_BASE = {
        "Port Scan": {
            "description": "Systematic probing of network ports to identify open services and potential vulnerabilities",
            "objectives": [
                "Identify active hosts",
                "Discover open ports and services",
                "Map network topology",
                "Find potential access points"
            ],
            "methodology": [
                "Send SYN packets to target ports",
                "Analyze responses to determine port state",
                "Probe multiple ports in sequence",
                "Often precedes targeted attacks"
            ],
            "attack_stage": AttackStage.RECONNAISSANCE,
            "mitre": {
                "techniques": ["T1046"],
                "tactics": ["Reconnaissance"],
                "technique_name": "Network Service Discovery",
                "technique_id": "T1046"
            },
            "affected_services": [
                "HTTP/HTTPS",
                "SSH",
                "Telnet",
                "FTP",
                "DNS",
                "SMTP"
            ],
            "indicators": [
                "High number of SYN packets",
                "Connections to many different ports",
                "Sequential port probing",
                "High port entropy",
                "Connections without successful handshake"
            ],
            "iocs": {
                "network": [
                    "Source IP performing scan",
                    "Destination ports targeted",
                    "Port range/entropy"
                ],
                "patterns": [
                    "SYN flood to multiple ports",
                    "Sequential port probing"
                ]
            },
            "impact": {
                "network": "Reconnaissance of network topology",
                "host": "None direct",
                "data": "None",
                "service": "Potential for targeted attacks",
                "business": "Medium - indicates reconnaissance phase"
            },
            "response": {
                "immediate": [
                    "Identify scanning source IP",
                    "Check for follow-up attacks",
                    "Review firewall logs"
                ],
                "short_term": [
                    "Block scanning source",
                    "Enable port-based alerting",
                    "Review open ports for necessity"
                ],
                "long_term": [
                    "Implement firewall rules",
                    "Close unnecessary ports",
                    "Enable port-based IDS signatures"
                ]
            },
            "prevention": [
                "Firewall rules to block unnecessary ports",
                "Rate limiting on connection attempts",
                "Port-based network segmentation",
                "IDS/IPS port scan detection"
            ],
            "references": [
                "MITRE ATT&CK T1046",
                "NIST SP 800-153"
            ]
        },
        
        "SSH Brute Force": {
            "description": "Repeated authentication attempts against SSH services to compromise credentials",
            "objectives": [
                "Gain unauthorized access to system",
                "Compromise user credentials",
                "Establish foothold for lateral movement"
            ],
            "methodology": [
                "Target SSH service (port 22)",
                "Attempt login with common credentials",
                "Use password dictionaries or lists",
                "Often automated and rapid"
            ],
            "attack_stage": AttackStage.CREDENTIAL_ACCESS,
            "mitre": {
                "techniques": ["T1110", "T1021"],
                "tactics": ["Credential Access", "Lateral Movement"],
                "technique_name": "Brute Force & Remote Services",
                "technique_ids": ["T1110", "T1021.004"]
            },
            "affected_services": [
                "SSH",
                "Linux/Unix Systems",
                "Windows with SSH"
            ],
            "indicators": [
                "Multiple failed login attempts from single IP",
                "Failed attempts for multiple usernames",
                "Rapid authentication attempts",
                "Success after multiple failures",
                "Failed logins from unusual IPs"
            ],
            "iocs": {
                "network": [
                    "Source IP",
                    "Destination (SSH service)",
                    "Port 22 or alternate SSH port"
                ],
                "host": [
                    "Target usernames",
                    "Failed login count",
                    "Failed login timestamps"
                ]
            },
            "impact": {
                "network": "Potential for compromised credentials",
                "host": "High - direct compromise risk",
                "data": "Access to all data accessible by compromised user",
                "service": "Service compromise, potential shutdown",
                "business": "Critical - full system access possible"
            },
            "response": {
                "immediate": [
                    "Block source IP at firewall",
                    "Check for successful logins",
                    "Review recent login history",
                    "Force password reset on targeted accounts"
                ],
                "short_term": [
                    "Disable weak accounts",
                    "Enable SSH key authentication",
                    "Implement account lockout policy",
                    "Enable multi-factor authentication"
                ],
                "long_term": [
                    "Deploy SSH honeypot",
                    "Implement IP whitelisting",
                    "Deploy fail2ban or equivalent",
                    "Regular security awareness training"
                ]
            },
            "prevention": [
                "Disable password authentication (use SSH keys)",
                "Enable account lockout (3-5 attempts)",
                "Implement rate limiting",
                "Use non-standard SSH port",
                "Deploy SSH hardening",
                "Monitor for brute force attempts"
            ],
            "references": [
                "MITRE ATT&CK T1110",
                "MITRE ATT&CK T1021",
                "CIS SSH Hardening Guide"
            ]
        },
        
        "DoS": {
            "description": "Attempt to overwhelm target with traffic to disrupt service availability",
            "objectives": [
                "Disrupt service availability",
                "Cause financial loss",
                "Mask other attacks"
            ],
            "methodology": [
                "Send high volume of packets",
                "Exploit protocol vulnerabilities",
                "Consume bandwidth or resources",
                "May target specific ports or services"
            ],
            "attack_stage": AttackStage.IMPACT,
            "mitre": {
                "techniques": ["T1498"],
                "tactics": ["Impact"],
                "technique_name": "Network Denial of Service",
                "technique_id": "T1498"
            },
            "affected_services": [
                "Web servers",
                "Application servers",
                "DNS services",
                "Any network service"
            ],
            "indicators": [
                "Abnormally high packet rate",
                "Traffic spike from single source",
                "Repeated connections to same port",
                "High bandwidth utilization",
                "Service performance degradation"
            ],
            "iocs": {
                "network": [
                    "Attacking source IP",
                    "Target service IP",
                    "Target port",
                    "Protocol used"
                ]
            },
            "impact": {
                "network": "Bandwidth exhaustion",
                "host": "Resource exhaustion",
                "data": "Service unavailability",
                "service": "Complete service disruption",
                "business": "Critical - service down, revenue impact"
            },
            "response": {
                "immediate": [
                    "Enable DDoS mitigation",
                    "Activate rate limiting",
                    "Block attacking IPs",
                    "Contact ISP for upstream filtering"
                ],
                "short_term": [
                    "Activate anti-DDoS service",
                    "Scale infrastructure",
                    "Enable advanced filtering"
                ],
                "long_term": [
                    "Deploy DDoS protection service",
                    "Implement geo-blocking if applicable",
                    "Redundancy and failover planning"
                ]
            },
            "prevention": [
                "DDoS mitigation service",
                "Rate limiting and throttling",
                "Firewall anti-DDoS rules",
                "ISP-level protection",
                "Redundant connectivity",
                "Load balancing"
            ],
            "references": [
                "MITRE ATT&CK T1498",
                "NIST DDoS Protection Guide"
            ]
        },
        
        "Privilege Escalation": {
            "description": "Unauthorized attempt to gain elevated system privileges",
            "objectives": [
                "Gain root/administrator access",
                "Bypass security controls",
                "Enable full system compromise"
            ],
            "methodology": [
                "Exploit kernel vulnerabilities",
                "Abuse sudo/sudoers configuration",
                "Exploit unpatched services",
                "Social engineering for escalation"
            ],
            "attack_stage": AttackStage.PRIVILEGE_ESCALATION,
            "mitre": {
                "techniques": ["T1548", "T1134"],
                "tactics": ["Privilege Escalation"],
                "technique_name": "Abuse Elevation Control Mechanism",
                "technique_ids": ["T1548.001", "T1134.001"]
            },
            "affected_services": [
                "Linux kernel",
                "Windows kernel",
                "Sudo",
                "UAC"
            ],
            "indicators": [
                "Unusual sudo usage",
                "Kernel module loading",
                "Privilege-escalation tool execution",
                "Capability modification",
                "SELinux/AppArmor bypass attempts"
            ],
            "iocs": {
                "host": [
                    "Process execution patterns",
                    "Sudo command usage",
                    "Kernel module loading",
                    "File modifications in /etc/sudoers"
                ]
            },
            "impact": {
                "network": "Full system compromise",
                "host": "Complete host compromise",
                "data": "Access to all data on system",
                "service": "Full control of all services",
                "business": "Critical - complete system control"
            },
            "response": {
                "immediate": [
                    "Immediately isolate affected host",
                    "Check for rootkit installation",
                    "Review system logs for changes",
                    "Check for backdoors"
                ],
                "short_term": [
                    "Full forensic analysis",
                    "System rebuild from clean backup",
                    "Change all credentials",
                    "Deploy enhanced monitoring"
                ],
                "long_term": [
                    "Patch management program",
                    "System hardening",
                    "HIPS deployment",
                    "Privilege access management"
                ]
            },
            "prevention": [
                "Keep systems patched",
                "Principle of least privilege",
                "Audit sudo usage",
                "Disable unnecessary services",
                "HIPS/IDS signatures",
                "File integrity monitoring"
            ],
            "references": [
                "MITRE ATT&CK T1548",
                "NIST Privileged Access Management"
            ]
        },
        
        "Unauthorized Access": {
            "description": "Successful login to system without proper authorization",
            "objectives": [
                "Establish persistent access",
                "Execute commands on system",
                "Prepare for lateral movement",
                "Steal data"
            ],
            "methodology": [
                "Use compromised credentials",
                "Exploit authentication bypass",
                "Use backdoor access",
                "Session hijacking"
            ],
            "attack_stage": AttackStage.INITIAL_ACCESS,
            "mitre": {
                "techniques": ["T1190", "T1133"],
                "tactics": ["Initial Access"],
                "technique_name": "Exploit Public-Facing Application",
                "technique_ids": ["T1190", "T1133"]
            },
            "affected_services": [
                "SSH",
                "RDP",
                "VPN",
                "Web applications"
            ],
            "indicators": [
                "Successful login after failed attempts",
                "Login from unusual location",
                "Login outside business hours",
                "Multiple simultaneous sessions",
                "Unusual command execution"
            ],
            "iocs": {
                "network": [
                    "Source IP",
                    "Destination system",
                    "Login timestamp"
                ],
                "host": [
                    "Username",
                    "Login time",
                    "Commands executed",
                    "Files accessed"
                ]
            },
            "impact": {
                "network": "System compromise and control",
                "host": "Full host compromise",
                "data": "Potential data theft",
                "service": "Service exploitation",
                "business": "Critical - unauthorized access"
            },
            "response": {
                "immediate": [
                    "Force session logout",
                    "Reset password",
                    "Review executed commands",
                    "Check for data access"
                ],
                "short_term": [
                    "Full audit of account activities",
                    "Check for persistence mechanisms",
                    "Review file modifications",
                    "Monitor for lateral movement"
                ],
                "long_term": [
                    "Implement multi-factor authentication",
                    "Enhanced session monitoring",
                    "Regular access reviews"
                ]
            },
            "prevention": [
                "Strong password policy",
                "Multi-factor authentication",
                "Account lockout policy",
                "Access logging and monitoring",
                "Principle of least privilege",
                "Regular access reviews"
            ],
            "references": [
                "MITRE ATT&CK T1190",
                "NIST Access Control Guide"
            ]
        }
    }
    
    def get_knowledge(self, attack_type: str) -> Optional[Dict]:
        """Get knowledge base entry for attack type"""
        return self.KNOWLEDGE_BASE.get(attack_type)
    
    def get_all_attacks(self) -> List[str]:
        """Get list of all known attacks"""
        return list(self.KNOWLEDGE_BASE.keys())
    
    def is_known_attack(self, attack_type: str) -> bool:
        """Check if attack type is in knowledge base"""
        return attack_type in self.KNOWLEDGE_BASE
    
    def get_mitre_info(self, attack_type: str) -> Optional[Dict]:
        """Get MITRE ATT&CK mapping for attack"""
        knowledge = self.get_knowledge(attack_type)
        if knowledge:
            return knowledge.get("mitre")
        return None
    
    def get_attack_stage(self, attack_type: str) -> Optional[AttackStage]:
        """Get attack lifecycle stage"""
        knowledge = self.get_knowledge(attack_type)
        if knowledge:
            return knowledge.get("attack_stage")
        return None
    
    def get_indicators(self, attack_type: str) -> Optional[List[str]]:
        """Get attack indicators"""
        knowledge = self.get_knowledge(attack_type)
        if knowledge:
            return knowledge.get("indicators", [])
        return None
    
    def get_iocs(self, attack_type: str) -> Optional[Dict]:
        """Get Indicators of Compromise"""
        knowledge = self.get_knowledge(attack_type)
        if knowledge:
            return knowledge.get("iocs", {})
        return None
    
    def get_impact(self, attack_type: str) -> Optional[Dict]:
        """Get impact assessment"""
        knowledge = self.get_knowledge(attack_type)
        if knowledge:
            return knowledge.get("impact", {})
        return None
    
    def get_response(self, attack_type: str) -> Optional[Dict]:
        """Get recommended response"""
        knowledge = self.get_knowledge(attack_type)
        if knowledge:
            return knowledge.get("response", {})
        return None
    
    def get_prevention(self, attack_type: str) -> Optional[List[str]]:
        """Get prevention recommendations"""
        knowledge = self.get_knowledge(attack_type)
        if knowledge:
            return knowledge.get("prevention", [])
        return None


# Global instance
threat_knowledge = ThreatKnowledgeBase()