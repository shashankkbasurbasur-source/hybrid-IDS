"""
IOC Generator
Extracts indicators of compromise from alerts
"""

from typing import Dict, List, Set
from datetime import datetime


class IOCGenerator:
    """Generates indicators of compromise from alerts"""
    
    def __init__(self):
        pass
    
    def extract_iocs(self, alert: Dict) -> Dict[str, List[str]]:
        """
        Extract IOCs from alert
        
        Returns:
            Dict with network, host, and file IOCs
        """
        
        iocs = {
            "network": self._extract_network_iocs(alert),
            "host": self._extract_host_iocs(alert),
            "file": self._extract_file_iocs(alert),
            "process": self._extract_process_iocs(alert)
        }
        
        return iocs
    
    def _extract_network_iocs(self, alert: Dict) -> List[Dict]:
        """Extract network indicators"""
        
        iocs = []
        
        nids_det = alert.get("nids_detection", {})
        if nids_det:
            # Source IP
            src_ip = nids_det.get("src_ip")
            if src_ip and src_ip != "0.0.0.0":
                iocs.append({
                    "type": "source_ip",
                    "value": src_ip,
                    "confidence": nids_det.get("confidence", 0),
                    "timestamp": datetime.utcnow().isoformat()
                })
            
            # Destination IP
            dst_ip = nids_det.get("dst_ip")
            if dst_ip and dst_ip != "0.0.0.0":
                iocs.append({
                    "type": "destination_ip",
                    "value": dst_ip,
                    "confidence": nids_det.get("confidence", 0),
                    "timestamp": datetime.utcnow().isoformat()
                })
            
            # Destination Port
            dst_port = nids_det.get("dst_port", 0)
            if dst_port > 0:
                iocs.append({
                    "type": "destination_port",
                    "value": str(dst_port),
                    "protocol": nids_det.get("protocol", "unknown"),
                    "confidence": nids_det.get("confidence", 0),
                    "timestamp": datetime.utcnow().isoformat()
                })
            
            # Protocol
            protocol = nids_det.get("protocol")
            if protocol and protocol != "OTHER":
                iocs.append({
                    "type": "protocol",
                    "value": protocol,
                    "confidence": nids_det.get("confidence", 0),
                    "timestamp": datetime.utcnow().isoformat()
                })
        
        return iocs
    
    def _extract_host_iocs(self, alert: Dict) -> List[Dict]:
        """Extract host indicators"""
        
        iocs = []
        
        hids_det = alert.get("hids_detection", {})
        if hids_det:
            # Source IP (host perspective)
            src_ip = hids_det.get("source_ip")
            if src_ip and src_ip != "0.0.0.0":
                iocs.append({
                    "type": "attacker_ip",
                    "value": src_ip,
                    "confidence": hids_det.get("confidence", 0),
                    "timestamp": datetime.utcnow().isoformat()
                })
            
            # Username
            username = hids_det.get("username")
            if username and username != "unknown":
                iocs.append({
                    "type": "username",
                    "value": username,
                    "targeted": True,
                    "confidence": hids_det.get("confidence", 0),
                    "timestamp": datetime.utcnow().isoformat()
                })
            
            # Hostname
            hostname = hids_det.get("hostname")
            if hostname and hostname != "unknown":
                iocs.append({
                    "type": "hostname",
                    "value": hostname,
                    "confidence": hids_det.get("confidence", 0),
                    "timestamp": datetime.utcnow().isoformat()
                })
            
            # Failed attempts
            failed_attempts = hids_det.get("failed_attempts", 0)
            if failed_attempts > 0:
                iocs.append({
                    "type": "failed_auth_count",
                    "value": str(failed_attempts),
                    "indicator": "Brute force indicator",
                    "confidence": hids_det.get("confidence", 0),
                    "timestamp": datetime.utcnow().isoformat()
                })
        
        return iocs
    
    def _extract_file_iocs(self, alert: Dict) -> List[Dict]:
        """Extract file indicators"""
        # Placeholder for file-based IOCs
        return []
    
    def _extract_process_iocs(self, alert: Dict) -> List[Dict]:
        """Extract process indicators"""
        # Placeholder for process-based IOCs
        return []
    
    def generate_ioc_report(self, iocs: Dict) -> str:
        """Generate human-readable IOC report"""
        
        report = "=== INDICATORS OF COMPROMISE ===\n\n"
        
        if iocs.get("network"):
            report += "NETWORK INDICATORS:\n"
            for ioc in iocs["network"]:
                report += f"  - {ioc['type'].upper()}: {ioc['value']}\n"
            report += "\n"
        
        if iocs.get("host"):
            report += "HOST INDICATORS:\n"
            for ioc in iocs["host"]:
                report += f"  - {ioc['type'].upper()}: {ioc['value']}\n"
            report += "\n"
        
        return report