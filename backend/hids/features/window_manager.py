"""
Shared window builder for the unified HIDS pipeline.

In live mode (window_seconds set) it keeps a rolling per-IP window
pruned by wall-clock age. In batch mode (window_seconds=None) it keeps
the full, unpruned per-IP event history for the duration of one
analyze() call — the whole uploaded file is one window per IP. Same
class, same ingest() call, used by both live and manual paths.
"""

import time
from collections import defaultdict, deque


class SlidingWindowManager:
    def __init__(self, window_seconds=None):
        self.window_seconds = window_seconds
        self._windows = defaultdict(deque)

    def ingest(self, ip, event):
        now = time.monotonic()
        window = self._windows[ip]
        window.append((now, event))

        if self.window_seconds is not None:
            while window and now - window[0][0] > self.window_seconds:
                window.popleft()

        return [e for _, e in window]