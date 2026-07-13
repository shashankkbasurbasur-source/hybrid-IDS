"""
Feature Extraction Queue (Module 11)
Per Step 3 spec: prepare the hook only, no detection logic yet.
Completed flows land here; Step 4 replaces the no-op consumer with real
feature extraction, then hands off to the detection_queue built in Step 2.
"""

import queue
import threading

from backend.core.logger import get_logger

logger = get_logger(__name__)


class FeatureExtractionQueue:
    def __init__(self, maxsize: int = 10000):
        self._queue = queue.Queue(maxsize=maxsize)
        self._worker_thread = None
        self._stop_event = threading.Event()
        self._dropped_count = 0

    def enqueue(self, completed_flow: dict):
        try:
            self._queue.put_nowait(completed_flow)
        except queue.Full:
            self._dropped_count += 1
            if self._dropped_count % 100 == 1:
                logger.warning(
                    f"Feature extraction queue full; dropped {self._dropped_count} flows so far"
                )

    def _noop_handler(self, flow: dict):
        # NO-OP placeholder — Step 4 replaces this with real feature extraction
        logger.debug(f"[NO-OP] Feature extraction queued flow: {flow['flow_key']}")

    def start_worker(self, handler=None):
        if self._worker_thread and self._worker_thread.is_alive():
            return

        handler = handler or self._noop_handler
        self._stop_event.clear()

        def _run():
            while not self._stop_event.is_set():
                try:
                    flow = self._queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                try:
                    handler(flow)
                except Exception as e:
                    logger.error(f"Feature extraction worker failed on {flow.get('flow_key')}: {e}")
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

    def dropped_count(self) -> int:
        return self._dropped_count


feature_extraction_queue = FeatureExtractionQueue()