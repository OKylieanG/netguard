"""
NetGuard — Database layer (SQLite)
Stores connection logs, firewall rules (allow/block), and app first-seen records.
"""

import sqlite3
import threading
import time
import os

DB_PATH = os.path.join(os.path.expanduser("~"), ".netguard", "netguard.db")


def _ensure_dir():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


def get_connection() -> sqlite3.Connection:
    _ensure_dir()
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


_lock = threading.Lock()


def init_db(conn: sqlite3.Connection):
    """Create tables if they don't exist."""
    with _lock:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS rules (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                exe_path    TEXT    NOT NULL UNIQUE,
                app_name    TEXT,
                action      TEXT    NOT NULL CHECK(action IN ('allow','block')),
                created_at  REAL    NOT NULL,
                updated_at  REAL    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS connection_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   REAL    NOT NULL,
                pid         INTEGER,
                exe_path    TEXT,
                app_name    TEXT,
                local_addr  TEXT,
                local_port  INTEGER,
                remote_addr TEXT,
                remote_port INTEGER,
                protocol    TEXT,
                status      TEXT,
                action      TEXT
            );

            CREATE TABLE IF NOT EXISTS first_seen (
                exe_path    TEXT PRIMARY KEY,
                app_name    TEXT,
                first_seen  REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_log_timestamp ON connection_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_log_exe ON connection_log(exe_path);
            CREATE INDEX IF NOT EXISTS idx_rules_exe ON rules(exe_path);
        """)
        conn.commit()


# ── Rule helpers ──────────────────────────────────────────────

def get_rule(conn, exe_path: str) -> dict | None:
    with _lock:
        row = conn.execute(
            "SELECT * FROM rules WHERE exe_path = ?", (exe_path,)
        ).fetchone()
    return dict(row) if row else None


def set_rule(conn, exe_path: str, app_name: str, action: str):
    now = time.time()
    with _lock:
        conn.execute("""
            INSERT INTO rules (exe_path, app_name, action, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(exe_path) DO UPDATE SET
                action=excluded.action,
                app_name=excluded.app_name,
                updated_at=excluded.updated_at
        """, (exe_path, app_name, action, now, now))
        conn.commit()


def delete_rule(conn, exe_path: str):
    with _lock:
        conn.execute("DELETE FROM rules WHERE exe_path = ?", (exe_path,))
        conn.commit()


def get_all_rules(conn) -> list[dict]:
    with _lock:
        rows = conn.execute(
            "SELECT * FROM rules ORDER BY updated_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


# ── Logging helpers ───────────────────────────────────────────

def log_connection(conn, *, pid, exe_path, app_name, local_addr, local_port,
                   remote_addr, remote_port, protocol, status, action):
    with _lock:
        conn.execute("""
            INSERT INTO connection_log
                (timestamp, pid, exe_path, app_name, local_addr, local_port,
                 remote_addr, remote_port, protocol, status, action)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (time.time(), pid, exe_path, app_name, local_addr, local_port,
              remote_addr, remote_port, protocol, status, action))
        conn.commit()


def get_log(conn, limit=500, exe_filter=None) -> list[dict]:
    with _lock:
        if exe_filter:
            rows = conn.execute(
                "SELECT * FROM connection_log WHERE exe_path = ? "
                "ORDER BY timestamp DESC LIMIT ?",
                (exe_filter, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM connection_log ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ).fetchall()
    return [dict(r) for r in rows]


# ── First-seen tracking ──────────────────────────────────────

def record_first_seen(conn, exe_path: str, app_name: str) -> bool:
    """Returns True if this is a NEW app (not previously seen)."""
    with _lock:
        existing = conn.execute(
            "SELECT 1 FROM first_seen WHERE exe_path = ?", (exe_path,)
        ).fetchone()
        if existing:
            return False
        conn.execute(
            "INSERT INTO first_seen (exe_path, app_name, first_seen) VALUES (?, ?, ?)",
            (exe_path, app_name, time.time())
        )
        conn.commit()
        return True
