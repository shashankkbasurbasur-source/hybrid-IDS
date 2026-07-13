"""
Performance Monitor — Module 9.
Tracks pipeline throughput/latency for thesis-grade evaluation metrics.
"""

import threading
import time

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False


class PerformanceMonitor:
    def __init__(self):
        self._lock = threading.Lock()
        self._flows_processed = 0
        self._total_inference_time_ms = 0.0
        self._dropped_flows = 0
        self._start_time = time.monotonic()

    def record_prediction(self, inference_time_ms: float):
        with self._lock:
            self._flows_processed += 1
            self._total_inference_time_ms += inference_time_ms

    def record_drop(self):
        with self._lock:
            self._dropped_flows += 1

    def snapshot(self, detection_queue_size: int, feature_queue_size: int) -> dict:
        with self._lock:
            elapsed = max(time.monotonic() - self._start_time, 0.001)
            avg_inference = (
                self._total_inference_time_ms / self._flows_processed
                if self._flows_processed else 0.0
            )
            data = {
                "flows_processed": self._flows_processed,
                "predictions_per_sec": round(self._flows_processed / elapsed, 3),
                "avg_inference_time_ms": round(avg_inference, 4),
                "dropped_flows": self._dropped_flows,
                "feature_queue_size": feature_queue_size,
                "detection_queue_size": detection_queue_size,
            }

        if _HAS_PSUTIL:
            process = psutil.Process()
            data["memory_mb"] = round(process.memory_info().rss / (1024 * 1024), 2)
            data["cpu_percent"] = process.cpu_percent(interval=0.1)
        else:
            data["memory_mb"] = None
            data["cpu_percent"] = None

        return data


performance_monitor = PerformanceMonitor()