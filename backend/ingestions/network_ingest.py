"""
Live Network Packet Capture Engine (NIDS ingestion) — FINAL VERSION.

Owns the full capture lifecycle (start/stop/pause/resume/restart), session
tracking, packet filtering, and dispatches every packet to the Device,
Flow, and Statistics managers. Flow completion (via FlowManager's timeout
logic) feeds the Detection Queue, whose worker threads (DetectionPipeline,
AlertManager) are started/stopped alongside capture but run independently
so slow ML inference never blocks packet capture.

This module should not require further architectural changes — Steps 3-7
extend the managers/hooks it calls, not this file itself.
"""

import threading
import time

from scapy.all import AsyncSniffer

from backend.ingestions.interface_manager import interface_manager, InterfaceState
from backend.ingestions.packet_parser import PacketParser
from backend.ingestions.packet_buffer import PacketBuffer
from backend.ingestions.packet_filter import packet_filter_manager
from backend.ingestions.capture_session import CaptureSession

from backend.storage.db_store import insert_packets_batch

from backend.detection.devices.device_manager import device_manager
from backend.detection.flows.flow_manager import flow_manager
from backend.detection.stats.statistic_manager import statistics_manager
from backend.detection.pipeline_hooks import detection_pipeline, alert_manager

from backend.core.exceptions import CaptureError
from backend.core.logger import get_logger

from backend.detection.protocols.protocol_analyzer import protocol_analyzer
from backend.detection.stats.network_statistics_manager import network_statistics_manager
from backend.detection.queues.feature_extraction_queue import feature_extraction_queue
from backend.storage.db_store import mark_devices_offline

logger = get_logger(__name__)


class CaptureStatus:
    IDLE = "IDLE"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    STOPPED = "STOPPED"
    ERROR = "ERROR"


class NetworkIngestor:
    """
    Central capture engine. One instance shared across the app
    (see `network_ingestor` singleton at the bottom of this file).
    """

    FLUSH_INTERVAL_SECONDS = 1.0
    STATS_SNAPSHOT_INTERVAL_SECONDS = 5.0
    BUFFER_MAX_SIZE = 50000

    def __init__(self):
        self._sniffer = None
        self._parser = PacketParser()
        self._buffer = PacketBuffer(max_size=self.BUFFER_MAX_SIZE)

        self._interface_name = None
        self._interface_ipv4 = None

        self._session = None
        self._status = CaptureStatus.IDLE

        self._paused = threading.Event()   # set = paused, packets dropped at callback
        self._stop_flush = threading.Event()
        self._flush_thread = None

        self._error_message = None
        self._lock = threading.RLock()

        self._last_stats_snapshot = time.monotonic()

    # =========================================================
    # Direction classification
    # =========================================================
    def _classify_direction(self, event: dict) -> str:
        """
        Classifies traffic relative to the capturing host's own IP.
        Falls back to 'unknown' if we don't know our own address yet.
        """
        local_ip = self._interface_ipv4
        if not local_ip or local_ip == "N/A":
            return "unknown"

        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")

        if src_ip == local_ip:
            return "outgoing"
        if dst_ip == local_ip:
            return "incoming"
        return "internal"

    # =========================================================
    # Sniffer callback — MUST be fast, no I/O, never raises
    # =========================================================
    def _on_packet(self, packet):
        
        if self._paused.is_set():
            return  # paused: drop silently, don't buffer, don't count

        event = self._parser.parse(packet, self._interface_name, self._session.session_id)

        if event.get("parse_error"):
            statistics_manager.update(event)
            return  # counted as a parsing error, never propagated further

        event["direction"] = self._classify_direction(event)

        # Post-parse filtering (protocol / IP / port). BPF filtering already
        # happened at the kernel level before we ever got here, if configured.
        if not packet_filter_manager.passes(event):
            return

        accepted = self._buffer.add(event)
        if not accepted:
            statistics_manager.record_drop()
            return

        # Architecture hooks — always called, so later steps never need to
        # touch this callback again.
        try:
            device_manager.update(event)
            flow_manager.update(event)
            statistics_manager.update(event)
            protocol_analyzer.update(event) 
        except Exception as e:
            logger.error(f"Hook update failed: {e}")

        interface_manager.mark_packet_received()


    # =========================================================
    # Background flush loop
    # =========================================================
    def _flush_loop(self):
        while not self._stop_flush.is_set():
            time.sleep(self.FLUSH_INTERVAL_SECONDS)
            self._flush()
            flow_manager.check_timeouts()  # drives flow completion -> detection_queue
            self._maybe_snapshot_stats()
            self._watchdog()
        self._flush()  # final flush when the loop is told to stop

    def _flush(self):
        batch = self._buffer.drain()
        if not batch:
            return

        try:
            insert_packets_batch(batch)
        except Exception as e:
            self._error_message = f"Database write failure: {e}"
            logger.error(self._error_message)

        device_manager.flush()
        flow_manager.flush()
        protocol_analyzer.flush() 

    def _maybe_snapshot_stats(self):
        now = time.monotonic()
        if now - self._last_stats_snapshot < self.STATS_SNAPSHOT_INTERVAL_SECONDS:
            return
        self._last_stats_snapshot = now

        statistics_manager.snapshot(
            session_id=self._session.session_id if self._session else None,
            active_flows=flow_manager.active_flow_count(),
            active_devices=device_manager.active_device_count(),
        )
        network_statistics_manager.build_snapshot(   # NEW
            session_id=self._session.session_id if self._session else None
        )
        try:
            mark_devices_offline(threshold_seconds=120)   # NEW — Module 12
        except Exception as e:
            logger.error(f"Failed to mark stale devices offline: {e}")

    def _watchdog(self):
        """
        Detects if the sniffer thread died unexpectedly (e.g. interface
        unplugged mid-capture) and performs the same guaranteed graceful
        shutdown sequence as an explicit stop() call.
        """
        if self._sniffer is None:
            return

        is_alive = getattr(self._sniffer, "running", False)
        if is_alive or self._status != CaptureStatus.RUNNING:
            return

        self._error_message = (
            f"Capture on '{self._interface_name}' stopped unexpectedly "
            "(interface may have disconnected)."
        )
        logger.error(self._error_message)

        self._status = CaptureStatus.ERROR
        interface_manager.set_state(InterfaceState.ERROR)

        self._graceful_shutdown_sequence(final_status="ERROR")
        self._sniffer = None

    # =========================================================
    # Guaranteed graceful shutdown sequence
    # Used by both stop() and the watchdog's error path, so flows/devices/
    # stats/session are ALWAYS finalized no matter how capture ends.
    # =========================================================
    def _graceful_shutdown_sequence(self, final_status: str):
        try:
            self._flush()
            flow_manager.force_flush_all()   # expire + enqueue all remaining flows
            device_manager.flush()
            statistics_manager.snapshot(
                session_id=self._session.session_id if self._session else None,
                active_flows=0,
                active_devices=device_manager.active_device_count(),
            )
        except Exception as e:
            logger.error(f"Error during graceful shutdown flush: {e}")
        finally:
            self._finalize_session(status=final_status)
            detection_pipeline.stop()
            alert_manager.stop()
            feature_extraction_queue.stop_worker() 

    def _finalize_session(self, status: str):
        if self._session is None:
            return
        stats = statistics_manager.as_dict()
        self._session.finalize(
            total_packets=stats["total_packets"],
            total_bytes=stats["total_bytes"],
            status=status,
        )

    # =========================================================
    # Capture control
    # =========================================================
    def start(self):
        with self._lock:
            if self._status == CaptureStatus.RUNNING:
                raise CaptureError("Capture is already running")

            current = interface_manager.current()  # raises if interface invalid/gone
            self._interface_name = current["interface"]["name"]
            self._interface_ipv4 = current["interface"]["ipv4"]

            statistics_manager.reset()
            self._buffer.drain()  # clear any stale data from a previous run
            self._error_message = None
            self._paused.clear()
            self._stop_flush.clear()
            self._last_stats_snapshot = time.monotonic()

            self._session = CaptureSession(self._interface_name)
            self._session.persist_start()

            sniffer_kwargs = {
                "iface": self._interface_name,
                "prn": self._on_packet,
                "store": False,
            }
            bpf = packet_filter_manager.get_bpf_filter()
            if bpf:
                sniffer_kwargs["filter"] = bpf

            self._sniffer = AsyncSniffer(**sniffer_kwargs)

            try:
                self._sniffer.start()
            except (OSError, PermissionError, RuntimeError) as e:
                self._sniffer = None
                self._status = CaptureStatus.ERROR
                interface_manager.set_state(InterfaceState.ERROR)
                raise CaptureError(
                    f"Failed to start capture on '{self._interface_name}': {e}"
                )

            self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
            self._flush_thread.start()

            # Start the decoupled detection/alert queue workers alongside capture
            detection_pipeline.start()
            alert_manager.start()
            feature_extraction_queue.start_worker()

            self._status = CaptureStatus.RUNNING
            interface_manager.set_state(InterfaceState.CAPTURING)

            logger.info(
                f"Capture started on {self._interface_name} "
                f"(session={self._session.session_id}, bpf={bpf or 'none'})"
            )

            return self.status()

    def pause(self):
        with self._lock:
            if self._status != CaptureStatus.RUNNING:
                raise CaptureError("Capture is not running; cannot pause")

            self._paused.set()
            self._status = CaptureStatus.PAUSED
            interface_manager.set_state(InterfaceState.PAUSED)

            logger.info(f"Capture paused (session={self._session.session_id})")
            return self.status()

    def resume(self):
        with self._lock:
            if self._status != CaptureStatus.PAUSED:
                raise CaptureError("Capture is not paused; cannot resume")

            self._paused.clear()
            self._status = CaptureStatus.RUNNING
            interface_manager.set_state(InterfaceState.CAPTURING)

            logger.info(f"Capture resumed (session={self._session.session_id})")
            return self.status()

    def stop(self):
        with self._lock:
            if self._sniffer is None and self._status not in (
                CaptureStatus.RUNNING, CaptureStatus.PAUSED
            ):
                raise CaptureError("Capture is not running")

            try:
                if self._sniffer:
                    self._sniffer.stop()
            except Exception as e:
                logger.warning(f"Sniffer stop raised (likely already dead): {e}")
            finally:
                self._sniffer = None

            self._stop_flush.set()
            if self._flush_thread:
                self._flush_thread.join(timeout=5)

            # Guaranteed graceful shutdown — flows/devices/stats/session
            # are always finalized, and queue workers always stopped.
            self._graceful_shutdown_sequence(final_status="STOPPED")

            self._status = CaptureStatus.STOPPED
            interface_manager.set_state(InterfaceState.STOPPED)

            logger.info(f"Capture stopped (session={self._session.session_id if self._session else 'n/a'})")

            return self.status()

    def restart(self):
        with self._lock:
            if self._status in (CaptureStatus.RUNNING, CaptureStatus.PAUSED):
                self.stop()
            return self.start()

    # =========================================================
    # Status / statistics for API + dashboard
    # =========================================================
    def status(self):
        is_running = self._sniffer is not None and getattr(self._sniffer, "running", False)
        stats = statistics_manager.as_dict()

        return {
            "is_running": is_running,
            "status": self._status,
            "interface": self._interface_name,
            "session_id": self._session.session_id if self._session else None,
            "buffer_size": self._buffer.size(),
            "buffer_dropped": self._buffer.dropped_count(),
            "error": self._error_message,
            **stats,
        }

    def live_statistics(self):
        stats = statistics_manager.as_dict()
        stats["packets_per_sec"] = (
            round(stats["total_packets"] / stats["duration_seconds"], 2)
            if stats["duration_seconds"] > 0 else 0
        )
        stats["active_flows"] = flow_manager.active_flow_count()
        stats["active_devices"] = device_manager.active_device_count()
        stats["session_id"] = self._session.session_id if self._session else None
        return stats


# Single shared instance used across the whole app
network_ingestor = NetworkIngestor()