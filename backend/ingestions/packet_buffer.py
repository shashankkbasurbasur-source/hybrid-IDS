"""
Packet Buffer Manager
Thread-safe buffer sitting between the sniffer callback (fast, no I/O)
and SQLite (batched, periodic writes). Configurable size and flush interval.
"""

import threading

from backend.core.exceptions import BufferOverflowError
from backend.core.logger import get_logger

logger = get_logger(__name__)


class PacketBuffer:
    def __init__(self, max_size: int = 50000):
        self._buffer = []
        self._lock = threading.Lock()
        self._max_size = max_size
        self._dropped_due_to_overflow = 0

    def add(self, event: dict) -> bool:
        """Returns False (and drops the event) if the buffer is full."""
        with self._lock:
            if len(self._buffer) >= self._max_size:
                self._dropped_due_to_overflow += 1
                if self._dropped_due_to_overflow % 1000 == 1:
                    logger.warning(
                        f"Packet buffer full ({self._max_size}); "
                        f"dropped {self._dropped_due_to_overflow} packets so far"
                    )
                return False
            self._buffer.append(event)
            return True

    def drain(self) -> list:
        with self._lock:
            if not self._buffer:
                return []
            batch = self._buffer
            self._buffer = []
            return batch

    def size(self) -> int:
        with self._lock:
            return len(self._buffer)

    def dropped_count(self) -> int:
        with self._lock:
            return self._dropped_due_to_overflow