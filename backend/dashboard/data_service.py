"""
Dashboard Data Service
Fetches data from backend APIs and databases for dashboard display
"""

import requests
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from backend.storage.nids_store import nids_db
import logging

logger = logging.getLogger(__name__)


class DashboardDataService:
    """Service to fetch dashboard data from backend"""
    
    def __init__(self, api_base_url: str = "http://localhost:8000/api"):
        self.api_base_url = api_base_url
        self.timeout = 5
    
    # ==================== SYSTEM STATUS ====================
    
    def get_system_health(self) -> Dict:
        """Get overall system health status"""
        try:
            response = requests.get(f"{self.api_base_url}/../health", timeout=self.timeout)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.error(f"Error fetching system health: {e}")
        
        return self._offline_status()
    
    def get_capture_status(self) -> Dict:
        """Get packet capture status"""
        try:
            # This would come from NIDS service
            stats = nids_db.get_capture_stats()
            return {
                "status": "operational",
                "packets_captured": stats.get("total_packets", 0),
                "active_flows": stats.get("active_flows", 0),
                "last_update": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Error fetching capture status: {e}")
            return {"status": "error", "message": str(e)}
    
    def get_hids_status(self) -> Dict:
        """Get HIDS monitoring status"""
        try:
            response = requests.get(f"{self.api_base_url}/hids/status", timeout=self.timeout)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.error(f"Error fetching HIDS status: {e}")
        
        return {"status": "unknown"}
    
    def _offline_status(self) -> Dict:
        """Return offline status"""
        return {
            "status": "offline",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    # ==================== NIDS DATA ====================
    
    def get_active_flows(self, limit: int = 100) -> List[Dict]:
        """Get active network flows"""
        try:
            stats = nids_db.get_capture_stats()
            # In production, this would come from a flows API endpoint
            return self._fetch_active_flows(limit)
        except Exception as e:
            logger.error(f"Error fetching active flows: {e}")
            return []
    
    def _fetch_active_flows(self, limit: int) -> List[Dict]:
        """Fetch flows from database"""
        try:
            # This is a placeholder - actual implementation would query flows from DB
            flows = []
            # Query would get recent flows with detection status
            return flows
        except Exception as e:
            logger.error(f"Error in _fetch_active_flows: {e}")
            return []
    
    def get_recent_packets(self, limit: int = 50) -> List[Dict]:
        """Get recently captured packets"""
        try:
            packets = nids_db.get_recent_packets(limit)
            return [
                {
                    "timestamp": p.get("timestamp"),
                    "src_ip": p.get("src_ip"),
                    "dst_ip": p.get("dst_ip"),
                    "protocol": p.get("protocol"),
                    "length": p.get("length"),
                    "flow_id": p.get("flow_id")
                }
                for p in packets
            ]
        except Exception as e:
            logger.error(f"Error fetching recent packets: {e}")
            return []
    
    def get_nids_detections(self, limit: int = 50) -> List[Dict]:
        """Get recent NIDS detections"""
        try:
            detections = nids_db.get_recent_detections(limit)
            return [
                {
                    "flow_id": d.get("flow_id"),
                    "timestamp": d.get("timestamp"),
                    "prediction": d.get("prediction"),
                    "attack_type": d.get("attack_type"),
                    "confidence": d.get("probability"),
                    "src_ip": d.get("src_ip"),
                    "dst_ip": d.get("dst_ip"),
                    "protocol": d.get("protocol")
                }
                for d in detections
            ]
        except Exception as e:
            logger.error(f"Error fetching NIDS detections: {e}")
            return []
    
    def get_protocol_distribution(self) -> Dict[str, int]:
        """Get distribution of protocols in captured packets"""
        try:
            packets = nids_db.get_recent_packets(1000)
            
            distribution = {}
            for packet in packets:
                protocol = packet.get("protocol", "OTHER")
                distribution[protocol] = distribution.get(protocol, 0) + 1
            
            return distribution
        except Exception as e:
            logger.error(f"Error calculating protocol distribution: {e}")
            return {}
    
    def get_top_ips(self, limit: int = 10) -> Dict[str, List]:
        """Get top source and destination IPs"""
        try:
            packets = nids_db.get_recent_packets(1000)
            
            src_ips = {}
            dst_ips = {}
            
            for packet in packets:
                src = packet.get("src_ip")
                if src:
                    src_ips[src] = src_ips.get(src, 0) + 1
                
                dst = packet.get("dst_ip")
                if dst:
                    dst_ips[dst] = dst_ips.get(dst, 0) + 1
            
            return {
                "source_ips": sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:limit],
                "destination_ips": sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:limit]
            }
        except Exception as e:
            logger.error(f"Error calculating top IPs: {e}")
            return {"source_ips": [], "destination_ips": []}
    
    # ==================== HIDS DATA ====================
    
    def get_active_sessions(self) -> List[Dict]:
        """Get active authentication sessions"""
        try:
            response = requests.get(
                f"{self.api_base_url}/hids/active-sessions",
                timeout=self.timeout
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("sessions", [])
        except Exception as e:
            logger.error(f"Error fetching active sessions: {e}")
        
        return []
    
    def get_hids_detections(self, limit: int = 50) -> List[Dict]:
        """Get recent HIDS detections"""
        try:
            response = requests.get(
                f"{self.api_base_url}/hids/detections?limit={limit}",
                timeout=self.timeout
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("detections", [])
        except Exception as e:
            logger.error(f"Error fetching HIDS detections: {e}")
        
        return []
    
    def get_authentication_timeline(self, hours: int = 1) -> List[Dict]:
        """Get authentication events over time"""
        try:
            # This would query HIDS events from past N hours
            response = requests.get(
                f"{self.api_base_url}/hids/active-sessions",
                timeout=self.timeout
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("sessions", [])
        except Exception as e:
            logger.error(f"Error fetching authentication timeline: {e}")
        
        return []
    
    def get_failed_login_stats(self) -> Dict:
        """Get failed login statistics"""
        try:
            sessions = self.get_active_sessions()
            
            stats = {
                "total_sessions": len(sessions),
                "total_failed": sum(s.get("failed_attempts", 0) for s in sessions),
                "total_successful": sum(s.get("successful_attempts", 0) for s in sessions),
                "top_users": self._get_top_users(sessions),
                "top_source_ips": self._get_top_source_ips(sessions)
            }
            
            return stats
        except Exception as e:
            logger.error(f"Error calculating failed login stats: {e}")
            return {}
    
    def _get_top_users(self, sessions: List[Dict], limit: int = 10) -> List:
        """Get top targeted users"""
        user_count = {}
        for session in sessions:
            users = session.get("users", [])
            for user in users:
                user_count[user] = user_count.get(user, 0) + 1
        
        return sorted(user_count.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    def _get_top_source_ips(self, sessions: List[Dict], limit: int = 10) -> List:
        """Get top source IPs"""
        ip_count = {}
        for session in sessions:
            ip = session.get("source_ip")
            if ip:
                ip_count[ip] = ip_count.get(ip, 0) + 1
        
        return sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    # ==================== ALERTS & INCIDENTS ====================
    
    def get_incidents(self, limit: int = 50, status: Optional[str] = None) -> List[Dict]:
        """Get incidents with optional status filter"""
        try:
            url = f"{self.api_base_url}/alerts/incidents?limit={limit}"
            if status:
                url += f"&status={status}"
            
            response = requests.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                return data.get("incidents", [])
        except Exception as e:
            logger.error(f"Error fetching incidents: {e}")
        
        return []
    
    def get_incident_detail(self, incident_id: str) -> Optional[Dict]:
        """Get detailed information about an incident"""
        try:
            response = requests.get(
                f"{self.api_base_url}/alerts/incidents/{incident_id}",
                timeout=self.timeout
            )
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.error(f"Error fetching incident detail: {e}")
        
        return None
    
    def get_alerts(self, limit: int = 50, severity: Optional[str] = None) -> List[Dict]:
        """Get alerts with optional severity filter"""
        try:
            url = f"{self.api_base_url}/alerts/alerts?limit={limit}"
            if severity:
                url += f"&severity={severity}"
            
            response = requests.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                return data.get("alerts", [])
        except Exception as e:
            logger.error(f"Error fetching alerts: {e}")
        
        return []
    
    def get_alert_statistics(self) -> Dict:
        """Get alert statistics"""
        try:
            alerts = nids_db.get_recent_alerts(1000)
            
            stats = {
                "total_alerts": len(alerts),
                "critical": len([a for a in alerts if a.get("severity") == "CRITICAL"]),
                "high": len([a for a in alerts if a.get("severity") == "HIGH"]),
                "medium": len([a for a in alerts if a.get("severity") == "MEDIUM"]),
                "low": len([a for a in alerts if a.get("severity") == "LOW"]),
                "active": len([a for a in alerts if a.get("status") == "active"]),
                "resolved": len([a for a in alerts if a.get("status") == "resolved"])
            }
            
            return stats
        except Exception as e:
            logger.error(f"Error calculating alert statistics: {e}")
            return {}
    
    # ==================== THREAT INTELLIGENCE ====================
    
    def get_threat_report(self, incident_id: str) -> Optional[Dict]:
        """Get threat intelligence report for incident"""
        try:
            response = requests.get(
                f"{self.api_base_url}/threat-intel/report/{incident_id}",
                timeout=self.timeout
            )
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.error(f"Error fetching threat report: {e}")
        
        return None
    
    def search_iocs(self, ioc_value: str) -> Optional[List[Dict]]:
        """Search for incidents by IOC"""
        try:
            response = requests.get(
                f"{self.api_base_url}/threat-intel/iocs?value={ioc_value}",
                timeout=self.timeout
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("results", [])
        except Exception as e:
            logger.error(f"Error searching IOCs: {e}")
        
        return None
    
    # ==================== STATISTICS ====================
    
    def get_dashboard_statistics(self) -> Dict:
        """Get overall dashboard statistics"""
        try:
            stats = {
                "packets_captured": nids_db.get_capture_stats().get("total_packets", 0),
                "alerts_total": self.get_alert_statistics(),
                "incidents_active": len(self.get_incidents(status="active")),
                "timestamp": datetime.utcnow().isoformat()
            }
            
            return stats
        except Exception as e:
            logger.error(f"Error fetching dashboard statistics: {e}")
            return {}


# Global instance
dashboard_data_service = DashboardDataService()