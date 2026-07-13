"""
Shared exception hierarchy for Hybrid IDS.
"""


class HybridIDSError(Exception):
    """Base class for all Hybrid IDS errors."""


class InterfaceError(HybridIDSError):
    """Raised for interface selection/validation/disconnection problems."""


class CaptureError(HybridIDSError):
    """Raised for capture engine failures (start/stop/sniffer crashes)."""


class BufferOverflowError(HybridIDSError):
    """Raised when the packet buffer exceeds its configured limit."""


class StorageError(HybridIDSError):
    """Raised for database write/read failures."""