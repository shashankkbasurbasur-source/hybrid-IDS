"""
Fusion Service - Complete Implementation
Orchestrates NIDS + HIDS detection, correlation, decision-making, 
alert generation, and threat intelligence enrichment
"""

from datetime import datetime, timedelta
from typing import Dict, Optional, List
from collections import deque
import threading

from backend.detection.correlation_engine import CorrelationEngine
from backend.detection.decision_engine import DecisionEngine
from backend.detection.alert_builder import AlertBuilder
from backend.intelligence.threat_intel_service import threat_intel_service
from backend.models.incident import Incident, AlertStatus
from backend.storage.nids_store import nids_db
import logging

logger = logging.getLogger(__name__)


class FusionService:
    """
    Central Hybrid IDS Fusion Service
    
    Responsibilities:
    1. Accept NIDS and HIDS detections
    2. Correlate them using temporal, spatial, and pattern analysis
    3. Make unified intrusion/normal decisions
    4. Classify attack severity
    5. Generate structured alerts/incidents
    6. Enrich with threat intelligence
    7. Store in persistent database
    8. Provide incident management APIs
    """
    
    def __init__(self):
        """Initialize fusion service components"""
        
        # Core engines
        self.correlation_engine = CorrelationEngine()
        self.decision_engine = DecisionEngine()
        self.alert_builder = AlertBuilder()
        
        # Pending detections waiting for correlation
        # Scapy can capture packets very fast, so we need a queue
        self.pending_nids: deque = deque(maxlen=500)  # Keep last 500 NIDS detections
        self.pending_hids: deque = deque(maxlen=500)  # Keep last 500 HIDS detections
        
        # Active incident tracking
        self.active_incidents: Dict[str, Incident] = {}
        
        # Lock for thread-safe operations
        self.lock = threading.Lock()
        
        # Statistics tracking
        self.stats = {
            "nids_detections_received": 0,
            "hids_detections_received": 0,
            "correlations_found": 0,
            "incidents_created": 0,
            "alerts_generated": 0,
            "hybrid_alerts": 0,
            "threat_reports_generated": 0,
            "timestamp_started": datetime.utcnow().isoformat()
        }
        
        logger.info("[Fusion Service] Initialized successfully")
    
    # ==================== DETECTION INPUT ====================
    
    def process_nids_detection(self, detection: Dict) -> Optional[str]:
        """
        Process incoming NIDS detection
        
        Workflow:
        1. Store detection with timestamp
        2. Attempt correlation with pending HIDS
        3. Create incident
        4. Make decision
        5. Generate alert
        6. Enrich with threat intelligence
        7. Store in database
        
        Args:
            detection: Dict with NIDS detection data
                {
                    'flow_id': str,
                    'src_ip': str,
                    'dst_ip': str,
                    'protocol': str,
                    'attack_type': str,
                    'score': float (0-1),
                    'confidence': float (0-1),
                    'packet_count': int,
                    'byte_count': int,
                    ...
                }
        
        Returns:
            incident_id if alert generated, None otherwise
        """
        
        try:
            # Add timestamp
            detection["timestamp"] = datetime.utcnow().isoformat()
            
            # Add to pending queue
            with self.lock:
                self.pending_nids.append(detection)
                self.stats["nids_detections_received"] += 1
            
            logger.debug(f"[NIDS Detection] Received: {detection.get('attack_type')} from {detection.get('src_ip')}")
            
            # Try to correlate with pending HIDS
            incident_id = self._attempt_correlation(detection, "nids")
            
            return incident_id
        
        except Exception as e:
            logger.error(f"[NIDS Processing Error] {str(e)}")
            return None
    
    def process_hids_detection(self, detection: Dict) -> Optional[str]:
        """
        Process incoming HIDS detection
        
        Workflow:
        1. Store detection with timestamp
        2. Attempt correlation with pending NIDS
        3. Create incident
        4. Make decision
        5. Generate alert
        6. Enrich with threat intelligence
        7. Store in database
        
        Args:
            detection: Dict with HIDS detection data
                {
                    'session_id': str,
                    'source_ip': str,
                    'username': str,
                    'attack_type': str,
                    'host_score': float (0-1),
                    'confidence': float (0-1),
                    'failed_attempts': int,
                    'successful_attempts': int,
                    ...
                }
        
        Returns:
            incident_id if alert generated, None otherwise
        """
        
        try:
            # Add timestamp
            detection["timestamp"] = datetime.utcnow().isoformat()
            
            # Add to pending queue
            with self.lock:
                self.pending_hids.append(detection)
                self.stats["hids_detections_received"] += 1
            
            logger.debug(f"[HIDS Detection] Received: {detection.get('attack_type')} from {detection.get('source_ip')}")
            
            # Try to correlate with pending NIDS
            incident_id = self._attempt_correlation(detection, "hids")
            
            return incident_id
        
        except Exception as e:
            logger.error(f"[HIDS Processing Error] {str(e)}")
            return None
    
    # ==================== CORRELATION ====================
    
    def _attempt_correlation(self, new_detection: Dict, 
                           source: str) -> Optional[str]:
        """
        Attempt to correlate new detection with pending detections
        
        Correlation logic:
        - Check temporal proximity (within configurable window)
        - Check spatial correlation (same IP, subnet, etc.)
        - Check pattern matching (known attack sequences)
        
        If correlation found:
            - Create hybrid incident
        If no correlation found within timeout:
            - Create standalone incident
        
        Args:
            new_detection: The new detection to correlate
            source: "nids" or "hids"
        
        Returns:
            incident_id of created incident
        """
        
        incident = None
        correlation_found = False
        
        try:
            if source == "nids":
                # NIDS detection - look for matching HIDS
                for hids_det in list(self.pending_hids):
                    # Check temporal correlation
                    time_diff = self._calculate_time_diff(
                        new_detection.get("timestamp"),
                        hids_det.get("timestamp")
                    )
                    
                    # Check if within correlation window (60 seconds)
                    if time_diff <= 60:
                        # Check IP correlation
                        nids_src = new_detection.get("src_ip", "")
                        hids_src = hids_det.get("source_ip", "")
                        
                        if nids_src == hids_src:
                            # Strong correlation found!
                            logger.info(
                                f"[Correlation] NIDS + HIDS correlated: "
                                f"{new_detection.get('attack_type')} + "
                                f"{hids_det.get('attack_type')} from {nids_src}"
                            )
                            
                            incident = self.correlation_engine.correlate(
                                new_detection, hids_det
                            )
                            
                            correlation_found = True
                            
                            # Remove matched HIDS from pending
                            with self.lock:
                                self.pending_hids.remove(hids_det)
                                self.stats["correlations_found"] += 1
                            
                            break
            
            else:  # HIDS
                # HIDS detection - look for matching NIDS
                for nids_det in list(self.pending_nids):
                    # Check temporal correlation
                    time_diff = self._calculate_time_diff(
                        new_detection.get("timestamp"),
                        nids_det.get("timestamp")
                    )
                    
                    # Check if within correlation window
                    if time_diff <= 60:
                        # Check IP correlation
                        nids_src = nids_det.get("src_ip", "")
                        hids_src = new_detection.get("source_ip", "")
                        
                        if nids_src == hids_src:
                            # Correlation found!
                            logger.info(
                                f"[Correlation] HIDS + NIDS correlated: "
                                f"{new_detection.get('attack_type')} + "
                                f"{nids_det.get('attack_type')} from {hids_src}"
                            )
                            
                            incident = self.correlation_engine.correlate(
                                nids_det, new_detection
                            )
                            
                            correlation_found = True
                            
                            # Remove matched NIDS from pending
                            with self.lock:
                                self.pending_nids.remove(nids_det)
                                self.stats["correlations_found"] += 1
                            
                            break
            
            # If no correlation found, create standalone incident
            if not incident:
                if source == "nids":
                    incident = self.correlation_engine.correlate(new_detection, None)
                    logger.debug("[Incident] Created NIDS-only incident")
                else:
                    incident = self.correlation_engine.correlate(None, new_detection)
                    logger.debug("[Incident] Created HIDS-only incident")
            
            # Step 1: Make Decision
            # Analyze evidence and determine if intrusion or normal
            incident = self.decision_engine.make_decision(incident)
            
            logger.debug(
                f"[Decision] {incident.decision.value} "
                f"(confidence: {incident.confidence:.2%})"
            )
            
            # Step 2: Build Alert
            # Create structured alert with evidence summary
            alert_dict = self.alert_builder.build_alert(incident)
            
            self.stats["alerts_generated"] += 1
            if incident.is_correlated:
                self.stats["hybrid_alerts"] += 1
            
            logger.debug(f"[Alert] Generated: {alert_dict.get('incident_id')}")
            
            # Step 3: Enrich with Threat Intelligence
            # Add MITRE mapping, attack stage, IOCs, risk assessment, etc.
            threat_report = threat_intel_service.analyze_alert(alert_dict)
            
            alert_dict["threat_report"] = threat_report
            self.stats["threat_reports_generated"] += 1
            
            logger.debug(f"[Threat Intel] Analysis complete for {alert_dict.get('incident_id')}")
            
            # Step 4: Store in Database
            # Persist alert and all evidence for later review
            nids_db.insert_alert(alert_dict)
            
            # Step 5: Track Active Incident
            # Store in memory for quick access by API
            with self.lock:
                self.active_incidents[incident.incident_id] = incident
            
            # Step 6: Log Summary
            self._log_incident_summary(incident, alert_dict)
            
            self.stats["incidents_created"] += 1
            
            return incident.incident_id
        
        except Exception as e:
            logger.error(f"[Correlation Error] {str(e)}", exc_info=True)
            return None
    
    def _calculate_time_diff(self, time1: str, time2: str) -> float:
        """Calculate time difference between two ISO format timestamps"""
        try:
            t1 = datetime.fromisoformat(time1)
            t2 = datetime.fromisoformat(time2)
            return abs((t1 - t2).total_seconds())
        except:
            return float('inf')  # Invalid timestamps = no correlation
    
    # ==================== INCIDENT MANAGEMENT ====================
    
    def get_incident(self, incident_id: str) -> Optional[Dict]:
        """
        Get incident by ID
        
        First checks in-memory active incidents for fast access.
        Falls back to database if not found in memory.
        
        Args:
            incident_id: Unique incident identifier
        
        Returns:
            Incident dict or None if not found
        """
        
        # Check active incidents first
        if incident_id in self.active_incidents:
            return self.active_incidents[incident_id].to_dict()
        
        # Fall back to database
        try:
            detections = nids_db.get_recent_detections(1000)
            for det in detections:
                if det.get("flow_id") == incident_id:
                    return det
        except Exception as e:
            logger.error(f"[Get Incident Error] {str(e)}")
        
        return None
    
    def acknowledge_incident(self, incident_id: str, analyst: str) -> bool:
        """
        Acknowledge incident (mark as reviewed)
        
        Args:
            incident_id: Incident to acknowledge
            analyst: Name of analyst acknowledging
        
        Returns:
            True if successful, False otherwise
        """
        
        try:
            if incident_id in self.active_incidents:
                incident = self.active_incidents[incident_id]
                incident.acknowledge(analyst)
                logger.info(f"[Acknowledged] {incident_id} by {analyst}")
                return True
        except Exception as e:
            logger.error(f"[Acknowledge Error] {str(e)}")
        
        return False
    
    def resolve_incident(self, incident_id: str, analyst: str) -> bool:
        """
        Resolve incident (close the case)
        
        Args:
            incident_id: Incident to resolve
            analyst: Name of analyst resolving
        
        Returns:
            True if successful, False otherwise
        """
        
        try:
            if incident_id in self.active_incidents:
                incident = self.active_incidents[incident_id]
                incident.resolve(analyst)
                logger.info(f"[Resolved] {incident_id} by {analyst}")
                return True
        except Exception as e:
            logger.error(f"[Resolve Error] {str(e)}")
        
        return False
    
    def add_incident_note(self, incident_id: str, analyst: str, note: str) -> bool:
        """
        Add analyst note to incident
        
        Args:
            incident_id: Incident to annotate
            analyst: Name of analyst adding note
            note: Note content
        
        Returns:
            True if successful, False otherwise
        """
        
        try:
            if incident_id in self.active_incidents:
                incident = self.active_incidents[incident_id]
                incident.add_note(analyst, note)
                logger.debug(f"[Note Added] {incident_id}")
                return True
        except Exception as e:
            logger.error(f"[Add Note Error] {str(e)}")
        
        return False
    
    # ==================== QUERIES ====================
    
    def get_active_incidents(self, limit: int = 50) -> List[Dict]:
        """
        Get list of active incidents
        
        Args:
            limit: Maximum number to return
        
        Returns:
            List of incident dicts, most recent first
        """
        
        try:
            with self.lock:
                incidents = [
                    inc.to_dict() 
                    for inc in list(self.active_incidents.values())[-limit:]
                ]
            
            # Sort by created_at descending
            incidents.sort(
                key=lambda x: x.get("created_at", ""),
                reverse=True
            )
            
            return incidents
        
        except Exception as e:
            logger.error(f"[Get Active Incidents Error] {str(e)}")
            return []
    
    def get_incidents_by_status(self, status: str, limit: int = 50) -> List[Dict]:
        """
        Get incidents filtered by status
        
        Args:
            status: "created", "active", "acknowledged", "resolved"
            limit: Maximum to return
        
        Returns:
            List of matching incidents
        """
        
        try:
            with self.lock:
                incidents = [
                    inc.to_dict() 
                    for inc in self.active_incidents.values()
                    if inc.status.value == status
                ]
            
            return incidents[-limit:]
        
        except Exception as e:
            logger.error(f"[Get Incidents by Status Error] {str(e)}")
            return []
    
    def get_incidents_by_severity(self, severity: str, limit: int = 50) -> List[Dict]:
        """
        Get incidents filtered by severity
        
        Args:
            severity: "LOW", "MEDIUM", "HIGH", "CRITICAL"
            limit: Maximum to return
        
        Returns:
            List of matching incidents
        """
        
        try:
            with self.lock:
                incidents = [
                    inc.to_dict() 
                    for inc in self.active_incidents.values()
                    if inc.severity.value == severity
                ]
            
            return incidents[-limit:]
        
        except Exception as e:
            logger.error(f"[Get Incidents by Severity Error] {str(e)}")
            return []
    
    def search_incidents(self, query: str, limit: int = 50) -> List[Dict]:
        """
        Search incidents by various criteria
        
        Args:
            query: Search term (IP, username, attack type, etc.)
            limit: Maximum to return
        
        Returns:
            List of matching incidents
        """
        
        try:
            results = []
            
            with self.lock:
                for incident in self.active_incidents.values():
                    incident_dict = incident.to_dict()
                    
                    # Search in multiple fields
                    if (
                        query.lower() in str(incident_dict.get("attack_type", "")).lower() or
                        query in incident_dict.get("source_ips", []) or
                        query in incident_dict.get("destination_ips", []) or
                        query in incident_dict.get("usernames", []) or
                        query in incident_dict.get("incident_id", "")
                    ):
                        results.append(incident_dict)
            
            return results[-limit:]
        
        except Exception as e:
            logger.error(f"[Search Incidents Error] {str(e)}")
            return []
    
    # ==================== STATISTICS ====================
    
    def get_statistics(self) -> Dict:
        """
        Get fusion service statistics
        
        Returns:
            Dict with various metrics
        """
        
        try:
            with self.lock:
                stats = self.stats.copy()
                stats["active_incidents"] = len(self.active_incidents)
                stats["pending_nids"] = len(self.pending_nids)
                stats["pending_hids"] = len(self.pending_hids)
                stats["timestamp_now"] = datetime.utcnow().isoformat()
                
                # Calculate rates
                if self.stats["nids_detections_received"] > 0:
                    correlation_rate = (
                        self.stats["correlations_found"] / 
                        self.stats["nids_detections_received"]
                    )
                    stats["correlation_rate"] = round(correlation_rate, 3)
                
                if self.stats["alerts_generated"] > 0:
                    hybrid_rate = (
                        self.stats["hybrid_alerts"] / 
                        self.stats["alerts_generated"]
                    )
                    stats["hybrid_rate"] = round(hybrid_rate, 3)
            
            return stats
        
        except Exception as e:
            logger.error(f"[Get Statistics Error] {str(e)}")
            return {}
    
    # ==================== LOGGING & DEBUGGING ====================
    
    def _log_incident_summary(self, incident: Incident, alert_dict: Dict):
        """Log a summary of the incident for audit trail"""
        
        try:
            summary = (
                f"[Incident] {incident.incident_id} | "
                f"Decision: {incident.decision.value} | "
                f"Attack: {incident.attack_type} | "
                f"Severity: {incident.severity.value} | "
                f"Confidence: {incident.confidence:.1%} | "
                f"Sources: {','.join(incident.source_ips)} | "
                f"Category: {incident.attack_category.value}"
            )
            
            logger.info(summary)
        
        except Exception as e:
            logger.error(f"[Log Summary Error] {str(e)}")
    
    def get_pending_detections(self) -> Dict[str, int]:
        """Get count of pending detections waiting for correlation"""
        
        with self.lock:
            return {
                "pending_nids": len(self.pending_nids),
                "pending_hids": len(self.pending_hids)
            }
    
    def get_incident_summary(self, incident_id: str) -> Optional[str]:
        """Get human-readable summary of incident"""
        
        incident = self.get_incident(incident_id)
        if not incident:
            return None
        
        summary = f"""
        Incident ID: {incident.get('incident_id')}
        Type: {incident.get('attack_type')}
        Severity: {incident.get('severity')}
        Decision: {incident.get('decision')}
        Confidence: {incident.get('confidence'):.1%}
        Status: {incident.get('status')}
        Created: {incident.get('created_at')}
        
        Sources: {', '.join(incident.get('source_ips', []))}
        Destinations: {', '.join(incident.get('destination_ips', []))}
        Users: {', '.join(incident.get('usernames', []))}
        
        Attack Category: {incident.get('attack_category')}
        Correlated: {incident.get('is_correlated')}
        Correlation Score: {incident.get('correlation_score'):.2%}
        """
        
        return summary


# ==================== GLOBAL INSTANCE ====================

# Single global fusion service instance
fusion_service = FusionService()


# ==================== USAGE EXAMPLES ====================

"""
USAGE EXAMPLES:

1. PROCESS NIDS DETECTION:
   
   nids_detection = {
       'flow_id': 'abc123',
       'src_ip': '192.168.1.100',
       'dst_ip': '8.8.8.8',
       'protocol': 'TCP',
       'attack_type': 'Port Scan',
       'score': 0.78,
       'confidence': 0.78,
       'packet_count': 150,
       'byte_count': 8945
   }
   
   incident_id = fusion_service.process_nids_detection(nids_detection)
   if incident_id:
       print(f"Incident created: {incident_id}")


2. PROCESS HIDS DETECTION:
   
   hids_detection = {
       'session_id': 'sess456',
       'source_ip': '192.168.1.100',
       'username': 'admin',
       'hostname': 'web-server-01',
       'attack_type': 'SSH Brute Force',
       'host_score': 0.85,
       'confidence': 0.85,
       'failed_attempts': 12,
       'successful_attempts': 1
   }
   
   incident_id = fusion_service.process_hids_detection(hids_detection)


3. GET ACTIVE INCIDENTS:
   
   incidents = fusion_service.get_active_incidents(limit=50)
   for incident in incidents:
       print(f"{incident['incident_id']}: {incident['attack_type']}")


4. GET INCIDENT DETAIL:
   
   incident = fusion_service.get_incident(incident_id)
   print(f"Severity: {incident['severity']}")
   print(f"Decision: {incident['decision']}")
   print(f"Threat Report: {incident.get('threat_report', {})}")


5. ACKNOWLEDGE INCIDENT:
   
   fusion_service.acknowledge_incident(incident_id, "john_doe")


6. ADD NOTE:
   
   fusion_service.add_incident_note(
       incident_id, 
       "john_doe", 
       "Confirmed as targeted attack on production servers"
   )


7. GET STATISTICS:
   
   stats = fusion_service.get_statistics()
   print(f"Total detections: {stats['nids_detections_received'] + stats['hids_detections_received']}")
   print(f"Alerts generated: {stats['alerts_generated']}")
   print(f"Hybrid rate: {stats.get('hybrid_rate', 0):.1%}")
"""