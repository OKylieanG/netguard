"""
Dimedropper — DNS Resolver
Caches reverse DNS lookups so the UI can show hostnames instead of raw IPs.
"""

import socket
import threading
import logging
from functools import lru_cache

logger = logging.getLogger("dimedropper.resolver")

_cache: dict[str, str] = {}
_lock = threading.Lock()
_pending: set[str] = set()


def resolve(ip: str) -> str:
    """
    Return a cached hostname for an IP, or the IP itself while resolution
    happens in the background.
    """
    with _lock:
        if ip in _cache:
            return _cache[ip]
        if ip in _pending:
            return ip  # Resolution in progress

    # Launch background resolution
    _pending.add(ip)
    t = threading.Thread(target=_do_resolve, args=(ip,), daemon=True)
    t.start()
    return ip


def _do_resolve(ip: str):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        with _lock:
            _cache[ip] = hostname
    except (socket.herror, socket.gaierror, OSError):
        with _lock:
            _cache[ip] = ip  # Cache the failure too
    finally:
        _pending.discard(ip)


def get_cached(ip: str) -> str:
    """Return cached result only, no background lookup."""
    with _lock:
        return _cache.get(ip, ip)
