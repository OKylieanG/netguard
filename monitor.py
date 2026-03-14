"""
NetGuard — Connection Monitor
Polls active network connections via psutil, detects new outbound connections,
and feeds events to callbacks.
"""

import os
import time
import threading
import logging
from dataclasses import dataclass, field
from typing import Callable

import psutil

logger = logging.getLogger("netguard.monitor")

POLL_INTERVAL = 1.0  # seconds


@dataclass
class ConnectionInfo:
    pid: int
    exe_path: str
    app_name: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    protocol: str  # "tcp" or "udp"
    status: str
    timestamp: float = field(default_factory=time.time)

    @property
    def key(self) -> str:
        """Unique key for deduplication within a monitoring window."""
        return f"{self.exe_path}|{self.remote_addr}|{self.remote_port}|{self.protocol}"


def _get_process_info(pid: int) -> tuple[str, str]:
    """Return (exe_path, app_name) for a PID."""
    try:
        proc = psutil.Process(pid)
        exe = proc.exe() or ""
        name = proc.name() or os.path.basename(exe) or f"PID {pid}"
        return exe, name
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "", f"PID {pid}"


def snapshot_connections() -> list[ConnectionInfo]:
    """Take a point-in-time snapshot of all connections with remote endpoints."""
    results = []
    seen_pids: dict[int, tuple[str, str]] = {}

    for kind, proto_label in [("tcp", "tcp"), ("udp", "udp")]:
        try:
            conns = psutil.net_connections(kind=kind)
        except (psutil.AccessDenied, PermissionError):
            logger.warning("Access denied reading %s connections — run as admin", kind)
            continue

        for c in conns:
            # Skip connections without a remote address or without a PID
            if not c.raddr or not c.pid:
                continue
            # Skip loopback
            if c.raddr.ip.startswith("127.") or c.raddr.ip == "::1":
                continue

            if c.pid not in seen_pids:
                seen_pids[c.pid] = _get_process_info(c.pid)
            exe_path, app_name = seen_pids[c.pid]

            status = c.status if hasattr(c, "status") and c.status else "n/a"

            results.append(ConnectionInfo(
                pid=c.pid,
                exe_path=exe_path,
                app_name=app_name,
                local_addr=c.laddr.ip if c.laddr else "",
                local_port=c.laddr.port if c.laddr else 0,
                remote_addr=c.raddr.ip,
                remote_port=c.raddr.port,
                protocol=proto_label,
                status=status,
            ))
    return results


class ConnectionMonitor:
    """
    Background thread that polls connections and fires callbacks:
      on_new_connection(ConnectionInfo)   — first time we see app→remote pair
      on_snapshot(list[ConnectionInfo])   — every poll cycle (for live table)
    """

    def __init__(self):
        self._running = False
        self._thread: threading.Thread | None = None
        self._seen_keys: set[str] = set()
        self._on_new: list[Callable] = []
        self._on_snapshot: list[Callable] = []
        # Keys expire after this many seconds to re-alert on long-lived connections
        self._key_ttl = 300  # 5 minutes
        self._key_timestamps: dict[str, float] = {}

    def on_new_connection(self, callback: Callable):
        self._on_new.append(callback)

    def on_snapshot(self, callback: Callable):
        self._on_snapshot.append(callback)

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="NetGuardMonitor")
        self._thread.start()
        logger.info("Connection monitor started")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
        logger.info("Connection monitor stopped")

    def _expire_old_keys(self):
        now = time.time()
        expired = [k for k, t in self._key_timestamps.items() if now - t > self._key_ttl]
        for k in expired:
            self._seen_keys.discard(k)
            del self._key_timestamps[k]

    def _loop(self):
        while self._running:
            try:
                conns = snapshot_connections()

                # Fire snapshot callbacks
                for cb in self._on_snapshot:
                    try:
                        cb(conns)
                    except Exception:
                        logger.exception("Error in snapshot callback")

                # Detect new connections
                self._expire_old_keys()
                for c in conns:
                    if c.key not in self._seen_keys:
                        self._seen_keys.add(c.key)
                        self._key_timestamps[c.key] = time.time()
                        for cb in self._on_new:
                            try:
                                cb(c)
                            except Exception:
                                logger.exception("Error in new-connection callback")

            except Exception:
                logger.exception("Error in monitor loop")

            time.sleep(POLL_INTERVAL)
