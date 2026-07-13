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

    def _noop_handler(self, incident: dict):
        logger.debug(f"[STEP 7 PENDING] Threat intel queue received incident: {incident.get('incident_id')}")

    def start_worker(self, handler=None):
        if self._worker_thread and self._worker_thread.is_alive():
            return
        handler = handler or self._noop_handler
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