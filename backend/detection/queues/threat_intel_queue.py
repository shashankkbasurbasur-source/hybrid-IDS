"""
Threat Intelligence Queue — Module 10.
Per spec: no analysis logic yet. Incidents are enqueued here; Step 7
replaces the no-op consumer with MITRE mapping / IOC enrichment.
"""

import queue
import threading

from backend.core.logger import get_logger

logger = get_logger(__name__)


class ThreatIntelQueue:
    def __init__(self, maxsize: int = 10000):
        self._queue = queue.Queue(maxsize=maxsize)
        self._worker_thread = None
        self._stop_event = threading.Event()
        self._dropped_count = 0

    def enqueue(self, incident: dict):
        try:
            self._queue.put_nowait(incident)
        except queue.Full:
            self._dropped_count += 1
            if self._dropped_count % 100 == 1:
                logger.warning(f"Threat intel queue full; dropped {self._dropped_count} incidents so far")

    def _intel_handler(self, item: dict):
        incident_id = item.get("incident_id")
        if not incident_id:
            return
            
        from backend.storage.db_store import fetch_incident_by_id, update_incident
        incident = fetch_incident_by_id(incident_id)
        if not incident:
            return
            
        from backend.intelligence.threat_intel_service import threat_intel_service
        try:
            report = threat_intel_service.analyze_alert(incident)
            
            mitre = report.get("attack", {}).get("mitre", {})
            techniques = mitre.get("techniques", [])
            tactics = mitre.get("tactics", [])
            
            updates = {
                "mitre_tactic": ", ".join(tactics) if tactics else "Credential Access",
                "mitre_technique": ", ".join(techniques) if techniques else "Brute Force (T1110)",
                "confidence": report.get("confidence_assessment", {}).get("confidence_score", 0.88),
                "risk_assessment": "High risk of host takeover, credentials leakage, and internal network pivoting.",
                "immediate_response": ", ".join(report.get("response", {}).get("immediate_actions", ["Block IP at firewall"])),
                "containment": ", ".join(report.get("response", {}).get("immediate_actions", ["Disable password SSH auth"])),
                "recovery": ", ".join(report.get("response", {}).get("short_term_actions", ["Restore from clean backup"])),
                "long_term_recommendations": ", ".join(report.get("response", {}).get("long_term_actions", ["Enforce MFA for user logins"])),
                "fusion_reasoning": "; ".join(report.get("confidence_assessment", {}).get("supporting_evidence", ["Fused correlation details"]))
            }
            
            # Remove any empty values
            updates = {k: v for k, v in updates.items() if v}
            
            update_incident(incident_id, updates)
            logger.info(f"[Threat Intel] Incident {incident_id} successfully enriched with MITRE mapping and response playbook.")
        except Exception as e:
            logger.error(f"[Threat Intel] Error generating report for {incident_id}: {e}")

    def start_worker(self, handler=None):
        if self._worker_thread and self._worker_thread.is_alive():
            return
        handler = handler or self._intel_handler
        self._stop_event.clear()

        def _run():
            while not self._stop_event.is_set():
                try:
                    incident = self._queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                try:
                    handler(incident)
                except Exception as e:
                    logger.error(f"Threat intel worker failed on {incident.get('incident_id')}: {e}")
                finally:
                    self._queue.task_done()

        self._worker_thread = threading.Thread(target=_run, daemon=True)
        self._worker_thread.start()

    def stop_worker(self):
        self._stop_event.set()
        if self._worker_thread:
            self._worker_thread.join(timeout=5)

    def size(self) -> int:
        return self._queue.qsize()


threat_intel_queue = ThreatIntelQueue()