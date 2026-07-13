"""
Reverse DNS Hostname Lookup
Runs off the capture thread (via a small worker pool) with a short timeout,
so a slow/unresponsive DNS server never stalls packet processing.
Results are cached — we only ever resolve a given IP once per process life.
"""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor

from backend.core.logger import get_logger

logger = get_logger(__name__)

_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="hostname-lookup")
_cache = {}
_cache_lock = threading.Lock()
_pending = set()


def _resolve(ip: str, timeout: float = 1.0) -> str:
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return "Unknown"
    finally:
        socket.setdefaulttimeout(old_timeout)


def _resolve_and_cache(ip: str):
    hostname = _resolve(ip)
    with _cache_lock:
        _cache[ip] = hostname
        _pending.discard(ip)
    logger.debug(f"Resolved hostname for {ip}: {hostname}")


def get_hostname_async(ip: str) -> str:
    """
    Returns the cached hostname immediately if known. If unknown, kicks off
    a background resolution and returns 'Unknown' for now — the next call
    (e.g. next flush cycle) will see the resolved value once it lands.
    """
    with _cache_lock:
        if ip in _cache:
            return _cache[ip]
        if ip in _pending:
            return "Unknown"
        _pending.add(ip)

    _executor.submit(_resolve_and_cache, ip)
    return "Unknown"