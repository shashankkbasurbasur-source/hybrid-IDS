"""
Interface Manager
Owns the "currently selected interface" state for the whole NIDS pipeline.
Discovery only reports interfaces; this decides, validates, tests, and
persists which one is active — surviving backend restarts.
"""

import os
import json
import socket
from datetime import datetime, timezone
from pathlib import Path

from backend.ingestions.interface_discovery import InterfaceDiscovery

STATE_FILE = Path("backend/storage/interface_state.json")


class InterfaceState:
    IDLE = "IDLE"
    CAPTURING = "CAPTURING"
    STOPPED = "STOPPED"
    PAUSED = "PAUSED"
    ERROR = "ERROR"


class InterfaceManager:
    """
    Singleton-style manager: discovers interfaces, scores/picks a default,
    validates + test-captures before accepting a selection, persists state
    to disk, tracks history, and exposes everything to NetworkIngestor.
    """

    TYPE_SCORE = {
        "Ethernet": 50,
        "Wireless": 50,
        "VPN": 10,
        "Unknown": 0,
        "Virtual": -100,
        "Loopback": -1000,
    }

    def __init__(self):
        self.discovery = InterfaceDiscovery()
        self._selected_interface = None
        self._capture_state = InterfaceState.IDLE
        self._state_started_at = None
        self._last_packet_at = None
        self._history = []  # list of {"name": ..., "selected_at": ...}, most recent last

        self._load_state()

    # -----------------------------
    # Persistence
    # -----------------------------
    def _load_state(self):
        if not STATE_FILE.exists():
            return
        try:
            data = json.loads(STATE_FILE.read_text())
            self._selected_interface = data.get("selected_interface")
            self._history = data.get("history", [])
        except (json.JSONDecodeError, OSError):
            # Corrupt or unreadable state file — start fresh rather than crash
            self._selected_interface = None
            self._history = []

    def _save_state(self):
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "selected_interface": self._selected_interface,
            "history": self._history[-20:],  # keep last 20 selections
        }
        try:
            STATE_FILE.write_text(json.dumps(payload, indent=2))
        except OSError:
            pass  # persistence is best-effort; don't crash the app over it

    # -----------------------------
    # Discovery passthrough
    # -----------------------------
    def discover(self):
        return self.discovery.list_interfaces()

    # -----------------------------
    # Scored default selection
    # -----------------------------
    def _score(self, iface: dict) -> int:
        score = self.TYPE_SCORE.get(iface["type"], 0)

        if iface["status"] == "UP":
            score += 50
        if iface["ipv4"] != "N/A":
            score += 40

        traffic = iface["packets_sent"] + iface["packets_received"]
        score += min(traffic, 10000) // 100  # capped contribution, avoids runaway counters

        return score

    def _pick_default(self, interfaces):
        if not interfaces:
            return None

        scored = sorted(interfaces, key=self._score, reverse=True)
        best = scored[0]

        # Refuse to default to something with a clearly disqualifying score
        if self._score(best) <= 0:
            return None

        return best["name"]

    # -----------------------------
    # Selection API
    # -----------------------------
    def select(self, interface_name: str, skip_test: bool = False):
        interfaces = self.discover()
        info = next((i for i in interfaces if i["name"] == interface_name), None)

        if info is None:
            raise ValueError(f"Interface '{interface_name}' not found")

        self.validate(interface_name, interfaces=interfaces)

        if not skip_test:
            self._test_capture(interface_name)

        self._selected_interface = interface_name
        self._history.append({
            "name": interface_name,
            "selected_at": datetime.now(timezone.utc).isoformat()
        })
        self._capture_state = InterfaceState.IDLE
        self._save_state()

        return self.current()

    def current(self):
        interfaces = self.discover()

        if self._selected_interface is None:
            default = self._pick_default(interfaces)
            if default is None:
                raise RuntimeError(
                    "No suitable interface found. Please select one manually."
                )
            self._selected_interface = default
            self._save_state()

        info = next(
            (i for i in interfaces if i["name"] == self._selected_interface),
            None
        )

        if info is None:
            previous = self._selected_interface
            self._capture_state = InterfaceState.ERROR
            self._selected_interface = None
            self._save_state()
            raise RuntimeError(
                f"Interface '{previous}' is disconnected. Please choose another interface."
            )

        return {
            "interface": info,
            "capture_state": self._capture_state,
            "state_started_at": self._state_started_at,
            "last_packet_at": self._last_packet_at,
            "history": self._history[-5:],  # last 5 selections for UI
        }

    def refresh(self):
        return self.current()

    # -----------------------------
    # Validation
    # -----------------------------
    def validate(self, interface_name: str, interfaces=None):
        interfaces = interfaces if interfaces is not None else self.discover()
        info = next((i for i in interfaces if i["name"] == interface_name), None)

        if info is None:
            raise ValueError(f"Interface '{interface_name}' not found")

        if info["status"] != "UP":
            raise ValueError(f"Interface '{interface_name}' is DOWN")

        if info["ipv4"] == "N/A":
            raise ValueError(
                f"Interface '{interface_name}' has no IPv4 address assigned — "
                "cannot capture meaningful traffic"
            )

        if not self._has_capture_permission():
            raise PermissionError(
                "Missing packet capture permission. "
                "Run with sudo or grant CAP_NET_RAW/CAP_NET_ADMIN "
                "(e.g. sudo setcap cap_net_raw,cap_net_admin=eip $(which python3))."
            )

        return True

    def _has_capture_permission(self) -> bool:
        try:
            return os.geteuid() == 0 or self._probe_raw_socket()
        except AttributeError:
            return True  # Windows: assume Npcap/WinPcap handles perms

    def _probe_raw_socket(self) -> bool:
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            s.close()
            return True
        except (PermissionError, OSError, AttributeError):
            return False

    # -----------------------------
    # Test capture — the "biggest missing feature"
    # -----------------------------
    def _test_capture(self, interface_name: str, timeout: float = 2.0):
        """
        Confirms the interface actually yields packets before accepting the
        selection. Prevents silently "selecting" a dead interface like docker0.
        """
        try:
            from scapy.all import sniff
        except ImportError:
            # Scapy not installed in this environment (e.g. during tests) — skip
            return

        try:
            packets = sniff(iface=interface_name, count=1, timeout=timeout)
        except (OSError, PermissionError) as e:
            raise RuntimeError(
                f"Test capture on '{interface_name}' failed: {e}"
            )

        if len(packets) == 0:
            raise RuntimeError(
                f"Test capture on '{interface_name}' captured no packets within "
                f"{timeout}s. It may be idle or not passing traffic. "
                "Select a different interface, or generate some traffic and retry."
            )

    # -----------------------------
    # Capture state control (used by Step 2)
    # -----------------------------
    def set_state(self, state: str):
        self._capture_state = state
        if state == InterfaceState.CAPTURING:
            self._state_started_at = datetime.now(timezone.utc).isoformat()

    def mark_packet_received(self):
        self._last_packet_at = datetime.now(timezone.utc).isoformat()

    def get_state(self):
        return self._capture_state


# Single shared instance — the source of truth across the app
interface_manager = InterfaceManager()