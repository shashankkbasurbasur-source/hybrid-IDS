# backend/detection/hybrid_fusion_engine.py
"""
The ONE Fusion Engine. Receives standardized detection objects from NIDS
and HIDS, correlates them by source IP + time window, computes final
confidence, severity, attack classification, and MITRE mapping, and
produces exactly one Hybrid Incident. No other module recomputes
severity or confidence.
"""

import threading
import time
from datetime import datetime, timezone
from collections import deque

from backend.core.constants import (
    FUSION_NETWORK_WEIGHT, FUSION_HOST_WEIGHT,
    HIGH_SEVERITY_THRESHOLD, MEDIUM_SEVERITY_THRESHOLD,
)
from backend.detection.mitre_mapper import MitreMapper
from backend.hids.alerts.alert_manager import build_and_dispatch_alert
from backend.core.logger import get_logger

log = get_logger("fusion_engine")

CORRELATION_WINDOW_SECONDS = 60


class HybridFusionEngine:
    def __init__(self):
        self._lock = threading.Lock()
        self._pending_nids = deque(maxlen=500)   # [(mono_time, detection, flow)]
        self._pending_hids = deque(maxlen=500)   # [(mono_time, detection)]
        self.mitre = MitreMapper()

    # -----------------------------------------------------
    # Entry points — called by NIDS and HIDS pipelines
    # -----------------------------------------------------
    def submit_nids_detection(self, detection: dict, flow: dict):
        if detection.get("prediction") != "Intrusion":
            return  # benign flow, nothing to fuse
        with self._lock:
            match = self._pop_matching_hids(flow.get("src_ip"))
            if match:
                self._create_incident(nids=detection, hids=match, flow=flow)
            else:
                self._pending_nids.append((time.monotonic(), detection, flow))

    def submit_hids_detection(self, detection: dict):
        with self._lock:
            match = self._pop_matching_nids(detection.get("source_ip"))
            if match:
                nids_det, flow = match
                self._create_incident(nids=nids_det, hids=detection, flow=flow)
            else:
                self._pending_hids.append((time.monotonic(), detection))

    # -----------------------------------------------------
    # Correlation (by source IP + time window)
    # -----------------------------------------------------
    def _pop_matching_hids(self, src_ip):
        if not src_ip:
            return None
        now = time.monotonic()
        for i, (t, det) in enumerate(self._pending_hids):
            if now - t > CORRELATION_WINDOW_SECONDS:
                continue
            if det.get("source_ip") == src_ip:
                del self._pending_hids[i]
                return det
        return None

    def _pop_matching_nids(self, src_ip):
        if not src_ip:
            return None
        now = time.monotonic()
        for i, (t, det, flow) in enumerate(self._pending_nids):
            if now - t > CORRELATION_WINDOW_SECONDS:
                continue
            if flow.get("src_ip") == src_ip:
                del self._pending_nids[i]
                return (det, flow)
        return None

    def sweep_expired(self):
        """Called periodically — NIDS-only or HIDS-only incidents after window expiry."""
        now = time.monotonic()
        with self._lock:
            expired_nids = [(d, f) for (t, d, f) in self._pending_nids if now - t > CORRELATION_WINDOW_SECONDS]
            expired_hids = [d for (t, d) in self._pending_hids if now - t > CORRELATION_WINDOW_SECONDS]
            self._pending_nids = deque(
                [(t, d, f) for (t, d, f) in self._pending_nids if now - t <= CORRELATION_WINDOW_SECONDS],
                maxlen=500,
            )
            self._pending_hids = deque(
                [(t, d) for (t, d) in self._pending_hids if now - t <= CORRELATION_WINDOW_SECONDS],
                maxlen=500,
            )
        for det, flow in expired_nids:
            self._create_incident(nids=det, hids=None, flow=flow)
        for det in expired_hids:
            self._create_incident(nids=None, hids=det, flow=None)

    # -----------------------------------------------------
    # Core decision logic — THE single place scores/severity/type are computed
    # -----------------------------------------------------
    def _create_incident(self, nids: dict | None, hids: dict | None, flow: dict | None):
        nids_score = float(nids.get("confidence", 0.0)) if nids else 0.0
        hids_score = float(hids.get("confidence", 0.0)) if hids else 0.0

        final_score = round(
            FUSION_NETWORK_WEIGHT * nids_score + FUSION_HOST_WEIGHT * hids_score, 4
        )

        is_correlated = bool(nids and hids)
        if is_correlated:
            attack_domain, attack_type = "Hybrid", "Multi-Stage Hybrid Attack"
        elif nids:
            attack_domain, attack_type = "Network", nids.get("attack_type", "Suspicious Network Activity")
        else:
            attack_domain, attack_type = "Host", hids.get("attack_type", "Suspicious Host Activity")

        max_score = max(nids_score, hids_score, final_score)
        if max_score >= 0.85:
            severity = "CRITICAL"
        elif max_score >= HIGH_SEVERITY_THRESHOLD:
            severity = "HIGH"
        elif max_score >= MEDIUM_SEVERITY_THRESHOLD:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        mitre_info = self.mitre.get_mitre_info(attack_type)

        reasoning = []
        if is_correlated:
            reasoning.append(f"NIDS and HIDS both flagged activity from the same source within {CORRELATION_WINDOW_SECONDS}s — correlated as one incident.")
        if nids:
            reasoning.append(f"NIDS: {nids.get('attack_type')} (confidence {nids_score:.2f})")
        if hids:
            reasoning.append(f"HIDS: {hids.get('attack_type')} (auth={hids.get('auth_score')}, syscall={hids.get('syscall_score')})")

        incident = {
            "incident_id": f"HYB-{int(time.time()*1000)}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": (flow or {}).get("src_ip") or (hids or {}).get("source_ip"),
            "attack_type": attack_type,
            "attack_domain": attack_domain,
            "severity": severity,
            "nids_score": round(nids_score, 4),
            "auth_score": (hids or {}).get("auth_score"),
            "syscall_score": (hids or {}).get("syscall_score"),
            "final_score": final_score,
            "is_correlated": is_correlated,
            "mitre": mitre_info,
            "reasoning": reasoning,
            "nids_detection": nids,
            "hids_detection": hids,
        }

        log.info(
            "Hybrid Incident created: %s | %s | severity=%s | final_score=%.3f | correlated=%s",
            incident["incident_id"], attack_type, severity, final_score, is_correlated,
        )

        self._dispatch(incident)
        return incident

    def _dispatch(self, incident: dict):
        from backend.storage.db_store import get_connection
        import json
        # Persist the unified incident (see section 6)
        conn = get_connection()
        with conn:
            conn.execute("""
                INSERT INTO hybrid_incidents
                (incident_id, timestamp, source_ip, attack_type, attack_domain,
                 severity, nids_score, auth_score, syscall_score, final_score,
                 is_correlated, mitre_json, reasoning_json, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident["incident_id"], incident["timestamp"], incident["source_ip"],
                incident["attack_type"], incident["attack_domain"], incident["severity"],
                incident["nids_score"], incident["auth_score"], incident["syscall_score"],
                incident["final_score"], int(incident["is_correlated"]),
                json.dumps(incident["mitre"]), json.dumps(incident["reasoning"]),
                json.dumps(incident, default=str),
            ))

        # Hand off to Alert Manager (section 4) — fusion NEVER builds alerts itself
        build_and_dispatch_alert(
            source_ip=incident["source_ip"],
            probability=incident["final_score"],
            attack_type=incident["attack_type"],
            severity=incident["severity"],
            mitre=incident["mitre"] or {},
            feature_vector=None,
            auth_score=incident["auth_score"],
            syscall_score=incident["syscall_score"],
        )


hybrid_fusion_engine = HybridFusionEngine()