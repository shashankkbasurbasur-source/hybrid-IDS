"""
Alert Queue
Decouples prediction results from alert generation / threat intelligence.
Detection worker pushes predictions here; alert worker consumes them.
"""

import queue
import threading

from backend.core.logger import get_logger

logger = get_logger(__name__)


class AlertQueue:
    def __init__(self, maxsize: int = 10000):
        self._queue = queue.Queue(maxsize=maxsize)
        self._worker_thread = None
        self._stop_event = threading.Event()
        self._dropped_count = 0

    def enqueue(self, prediction: dict):
        try:
            self._queue.put_nowait(prediction)
        except queue.Full:
            self._dropped_count += 1
            if self._dropped_count % 100 == 1:
                logger.warning(
                    f"Alert queue full; dropped {self._dropped_count} predictions so far"
                )

    def start_worker(self, handler):
        if self._worker_thread and self._worker_thread.is_alive():
            return

        self._stop_event.clear()

        def _run():
            while not self._stop_event.is_set():
                try:
                    prediction = self._queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                try:
                    handler(prediction)
                except Exception as e:
                    logger.error(f"Alert worker failed on prediction {prediction.get('prediction_id')}: {e}")
                finally:
                    self._queue.task_done()

        self._worker_thread = threading.Thread(target=_run, daemon=True)
        self._worker_thread.start()
        logger.info("Alert queue worker started")

    def stop_worker(self):
        self._stop_event.set()
        if self._worker_thread:
            self._worker_thread.join(timeout=5)

    def size(self) -> int:
        return self._queue.qsize()

    def dropped_count(self) -> int:
        return self._dropped_count


alert_queue = AlertQueue()