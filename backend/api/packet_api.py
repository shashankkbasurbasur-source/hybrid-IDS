"""
backend/api/packet_api.py

Live packet capture and network-focused detection endpoints.
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional, List
import threading
import pandas as pd

from backend.ingestions.network_ingest import NetworkIngestor
from backend.features.network_features import NetworkFeatureExtractor
from backend.detection.service import run_hybrid_detection
from backend.scenarios.attack_generators import (
    generate_normal_traffic, generate_port_scan, 
    generate_ddos_flood, generate_ssh_brute_force, generate_hybrid_attack
)
from backend.core.logger import get_logger
from backend.core.exceptions import IngestionError

logger = get_logger(__name__)
router = APIRouter()

# State for continuous capture
_capture_state = {"running": False, "packet_count": 0, "alerts": []}
_capture_lock = threading.Lock()


class CaptureRequest(BaseModel):
    packet_count: int = Field(100, ge=1, le=1000)
    interface: Optional[str] = Field(None, description="Network interface (eth0, wlan0, etc)")
    timeout: int = Field(10, ge=1, le=60)


class ScenarioRequest(BaseModel):
    scenario: str = Field(..., description="normal | port_scan | ddos | brute_force | hybrid")
    packet_count: int = Field(50, ge=1, le=500)


# ─────────────────────────────────────────────────────────────────────────────
# LIVE PACKET CAPTURE
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/capture")
def capture_packets(req: CaptureRequest, background_tasks: BackgroundTasks):
    """
    Capture live network packets and run NIDS detection.
    Returns real-time detection results.
    """
    try:
        logger.info("[PACKET API] Starting capture: %d packets from %s", 
                    req.packet_count, req.interface or "default")
        
        # Network ingest
        ingestor = NetworkIngestor(
            packet_count=req.packet_count,
            interface=req.interface,
            timeout=req.timeout
        )
        net_events = ingestor.ingest()
        
        if not net_events:
            return {
                "status": "success",
                "packets_captured": 0,
                "alerts": [],
                "message": "No packets captured (check interface or permissions)"
            }
        
        # Extract features
        extractor = NetworkFeatureExtractor()
        net_features = extractor.extract(net_events)
        
        # Run detection (NIDS path with zero HIDS for now)
        result = run_hybrid_detection(net_features, [0.0] * 100)
        
        return {
            "status": "success",
            "packets_captured": len(net_events),
            "network_features": {
                "packet_count": len(net_events),
                "total_bytes": sum(e.get("length", 0) for e in net_events),
                "protocols": list(set(e.get("protocol", "OTHER") for e in net_events)),
                "unique_src_ips": len(set(e.get("src_ip", "") for e in net_events)),
                "unique_dst_ips": len(set(e.get("dst_ip", "") for e in net_events)),
            },
            "detection_result": result,
        }
    except IngestionError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("Packet capture error")
        raise HTTPException(status_code=500, detail=str(e))


# ─────────────────────────────────────────────────────────────────────────────
# TEST ATTACK SCENARIOS
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/scenario/test")
def test_scenario(req: ScenarioRequest):
    """
    Test NIDS/HIDS against simulated attack scenarios.
    Does NOT generate actual attack traffic — purely for testing detection.
    """
    try:
        net_events = []
        log_lines = []
        scenario_name = req.scenario.lower()
        
        if scenario_name == "normal":
            net_events = generate_normal_traffic(req.packet_count)
        elif scenario_name == "port_scan":
            net_events = generate_port_scan(req.packet_count)
        elif scenario_name == "ddos":
            net_events = generate_ddos_flood(req.packet_count)
        elif scenario_name == "brute_force":
            log_lines = generate_ssh_brute_force(req.packet_count)
            net_events = []  # HIDS-only
        elif scenario_name == "hybrid":
            net_events, log_lines = generate_hybrid_attack()
        else:
            raise HTTPException(status_code=400, 
                              detail=f"Unknown scenario: {scenario_name}")
        
        # Extract features
        net_extractor = NetworkFeatureExtractor()
        net_features = net_extractor.extract(net_events) if net_events else [0.0] * 78
        
        from backend.features.log_features import LogFeatureExtractor
        from backend.parsing.ssh_parser import SSHLogParser
        
        host_features = [0.0] * 100
        if log_lines:
            parser = SSHLogParser()
            events = [parser.parse_line(l) for l in log_lines]
            events = [e for e in events if e is not None]
            log_extractor = LogFeatureExtractor()
            host_features = log_extractor.extract(events)
            
        print("Network Features:", net_features[:10] if net_features else "None")
        print("Host Features:", host_features[:10] if host_features else "None")
        
        # Run detection
        result = run_hybrid_detection(net_features, host_features)
        
        return {
            "status": "success",
            "scenario": scenario_name,
            "events_generated": {
                "network_events": len(net_events),
                "log_lines": len(log_lines),
            },
            "detection_result": result,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Scenario test error")
        raise HTTPException(status_code=500, detail=str(e))


# ─────────────────────────────────────────────────────────────────────────────
# PACKET STATISTICS
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/stats", summary="Packet capture statistics")
def packet_stats():
    """Return REAL-TIME packet capture and alert statistics."""
    try:
        # Get alert counts from storage
        from backend.storage.db_store import alert_store
        
        alert_stats = alert_store.stats()
        
        return {
            "status": "OK",
            "capture_active": _capture_state["running"],
            "total_packets_captured": _capture_state["packet_count"],
            "total_alerts_generated": alert_stats.get("total", 0),
            "alerts_by_severity": alert_stats.get("by_severity", {}),
            "alerts_by_decision": alert_stats.get("by_decision", {}),
            "timestamp": str(pd.Timestamp.now()),
        }
    except Exception as e:
        logger.exception("Stats retrieval failed")
        return {
            "status": "ERROR",
            "error": str(e),
        }