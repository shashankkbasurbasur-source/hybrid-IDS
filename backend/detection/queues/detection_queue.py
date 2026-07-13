"""
Detection Queue — with retry + dead-letter handling (Module 8 fix).
"""

import json
import queue
import threading

from backend.storage.db_store import insert_dead_letter
from backend.core.logger import get_logger

logger = get_logger(__name__)

MAX_RETRIES = 2


class DetectionQueue:
    def __init__(self, maxsize: int = 10000):
        self._queue = queue.Queue(maxsize=maxsize)
        self._worker_thread = None
        self._stop_event = threading.Event()
        self._dropped_count = 0

    def enqueue(self, item: dict, retry_count: int = 0):
        payload = {"item": item, "retry_count": retry_count}
        try:
            self._queue.put_nowait(payload)
        except queue.Full:
            self._dropped_count += 1
            if self._dropped_count % 100 == 1:
                logger.warning(f"Detection queue full; dropped {self._dropped_count} items so far")
            self._to_dead_letter(item, "Queue full", retry_count)

    def _to_dead_letter(self, item: dict, error: str, retry_count: int):
        try:
            insert_dead_letter("detection_queue", json.dumps(item, default=str), error, retry_count)
        except Exception as e:
            logger.error(f"Failed to write to dead letter queue: {e}")

    def start_worker(self, handler):
        if self._worker_thread and self._worker_thread.is_alive():
            return

        self._stop_event.clear()

        def _run():
            while not self._stop_event.is_set():
                try:
                    payload = self._queue.get(timeout=1.0)
                except queue.Empty:
                    continue

                item, retry_count = payload["item"], payload["retry_count"]
                try:
                    handler(item)
                except Exception as e:
                    if retry_count < MAX_RETRIES:
                        logger.warning(
                            f"Detection worker failed (retry {retry_count + 1}/{MAX_RETRIES}): {e}"
                        )
                        self.enqueue(item, retry_count=retry_count + 1)
                    else:
                        logger.error(f"Detection worker failed permanently after retries: {e}")
                        self._to_dead_letter(item, str(e), retry_count)
                finally:
                    self._queue.task_done()

        self._worker_thread = threading.Thread(target=_run, daemon=True)
        self._worker_thread.start()
        logger.info("Detection queue worker started")

    def stop_worker(self):
        self._stop_event.set()
        if self._worker_thread:
            self._worker_thread.join(timeout=5)

    def size(self) -> int:
        return self._queue.qsize()

    def dropped_count(self) -> int:
        return self._dropped_count


detection_queue = DetectionQueue()