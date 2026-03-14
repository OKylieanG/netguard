"""
Dimedropper — Main Application
System tray icon with popup notifications and a dashboard window.
"""

import os
import sys
import time
import hashlib
import threading
import webbrowser
import urllib.parse
import logging
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from collections import defaultdict

# These will be available on Windows; we handle import gracefully for dev
try:
    import pystray
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    pystray = None
    Image = None
    ImageDraw = None

from monitor import ConnectionMonitor, ConnectionInfo, snapshot_connections
from database import (
    get_connection, init_db, get_rule, set_rule, delete_rule,
    get_all_rules, log_connection, get_log, record_first_seen,
)
from firewall import is_admin, block_app, allow_app, remove_rule, sync_rule_to_firewall
from resolver import resolve

logger = logging.getLogger("dimedropper")

# ── Configuration ─────────────────────────────────────────────

ALERT_NEW_APPS = True       # Show popup for never-before-seen apps
ALERT_UNKNOWN_APPS = True   # Show popup for apps without a rule
LOG_ALL_CONNECTIONS = True   # Log every connection to the database


# ── Tray Icon Generation ─────────────────────────────────────

def _create_icon_image(size=64, color_bg=(30, 30, 40), color_shield=(80, 180, 255)):
    """Create a simple shield icon for the tray."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Shield shape
    cx, cy = size // 2, size // 2
    s = size * 0.4
    points = [
        (cx, cy - s),             # top
        (cx + s * 0.85, cy - s * 0.5),  # top-right
        (cx + s * 0.7, cy + s * 0.5),   # bottom-right
        (cx, cy + s),             # bottom
        (cx - s * 0.7, cy + s * 0.5),   # bottom-left
        (cx - s * 0.85, cy - s * 0.5),  # top-left
    ]
    draw.polygon(points, fill=color_shield, outline=(255, 255, 255, 200))

    # "N" letter in center
    try:
        font = ImageFont.truetype("arial.ttf", size // 3)
    except (OSError, IOError):
        font = ImageFont.load_default()
    bbox = draw.textbbox((0, 0), "N", font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    draw.text((cx - tw // 2, cy - th // 2 - 2), "N", fill=(255, 255, 255), font=font)
    return img


# ── Alert Popup ───────────────────────────────────────────────

class AlertPopup:
    """
    A toast-style popup window that appears when a new app makes a connection.
    Offers Allow / Block / Dismiss actions.
    """

    _active_popups: list = []

    def __init__(self, conn_info: ConnectionInfo, db_conn, on_decision=None):
        self.conn = conn_info
        self.db_conn = db_conn
        self.on_decision = on_decision
        self.result = None

        self.root = tk.Tk()
        self.root.title("Dimedropper Alert")
        self.root.attributes("-topmost", True)
        self.root.overrideredirect(False)
        self.root.resizable(False, False)
        self.root.configure(bg="#1e1e2e")

        # Position at bottom-right of screen
        offset = len(AlertPopup._active_popups) * 220
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        win_w, win_h = 480, 210
        x = screen_w - win_w - 20
        y = screen_h - win_h - 60 - offset
        self.root.geometry(f"{win_w}x{win_h}+{x}+{y}")

        AlertPopup._active_popups.append(self)

        self._build_ui()
        self.root.after(30000, self._auto_dismiss)  # Auto-dismiss after 30s

    def _build_ui(self):
        frame = tk.Frame(self.root, bg="#1e1e2e", padx=15, pady=10)
        frame.pack(fill="both", expand=True)

        # Header
        tk.Label(
            frame, text="⚡ New Connection Detected",
            bg="#1e1e2e", fg="#89b4fa", font=("Segoe UI", 11, "bold")
        ).pack(anchor="w")

        # App info
        app_name = self.conn.app_name or os.path.basename(self.conn.exe_path)
        tk.Label(
            frame, text=app_name,
            bg="#1e1e2e", fg="#cdd6f4", font=("Segoe UI", 13, "bold")
        ).pack(anchor="w", pady=(5, 0))

        # Connection details
        hostname = resolve(self.conn.remote_addr)
        detail = f"→  {hostname}:{self.conn.remote_port}  ({self.conn.protocol.upper()})"
        tk.Label(
            frame, text=detail,
            bg="#1e1e2e", fg="#a6adc8", font=("Consolas", 9)
        ).pack(anchor="w")

        path_display = self.conn.exe_path if len(self.conn.exe_path) < 55 else "..." + self.conn.exe_path[-52:]
        tk.Label(
            frame, text=path_display,
            bg="#1e1e2e", fg="#585b70", font=("Consolas", 8)
        ).pack(anchor="w", pady=(2, 0))

        # Buttons
        btn_frame = tk.Frame(frame, bg="#1e1e2e")
        btn_frame.pack(fill="x", pady=(12, 0))

        btn_style = {"font": ("Segoe UI", 9, "bold"), "width": 8, "cursor": "hand2", "relief": "flat", "bd": 0}

        tk.Button(
            btn_frame, text="✓ Allow", bg="#a6e3a1", fg="#1e1e2e",
            command=lambda: self._decide("allow"), **btn_style
        ).pack(side="left", padx=(0, 6))

        tk.Button(
            btn_frame, text="✕ Block", bg="#f38ba8", fg="#1e1e2e",
            command=lambda: self._decide("block"), **btn_style
        ).pack(side="left", padx=(0, 6))

        tk.Button(
            btn_frame, text="🔍 Research", bg="#cba6f7", fg="#1e1e2e",
            command=self._research, **btn_style
        ).pack(side="left", padx=(0, 6))

        tk.Button(
            btn_frame, text="Dismiss", bg="#45475a", fg="#cdd6f4",
            command=self._dismiss, **btn_style
        ).pack(side="left")

    def _research(self):
        exe = self.conn.exe_path
        app_name = self.conn.app_name or os.path.basename(exe)

        win = tk.Toplevel(self.root)
        win.title(f"Research: {app_name}")
        win.configure(bg="#1e1e2e")
        win.geometry("520x280")
        win.attributes("-topmost", True)
        win.resizable(False, False)

        frame = tk.Frame(win, bg="#1e1e2e", padx=16, pady=12)
        frame.pack(fill="both", expand=True)

        tk.Label(
            frame, text=f"🔍  {app_name}", bg="#1e1e2e", fg="#89b4fa",
            font=("Segoe UI", 12, "bold")
        ).pack(anchor="w")

        tk.Label(
            frame, text=exe, bg="#1e1e2e", fg="#585b70",
            font=("Consolas", 8), wraplength=488, justify="left"
        ).pack(anchor="w", pady=(3, 0))

        # File size
        try:
            size = os.path.getsize(exe)
            size_str = f"{size:,} bytes  ({size / 1024 / 1024:.2f} MB)"
        except OSError:
            size_str = "unavailable"
        tk.Label(
            frame, text=f"Size:    {size_str}", bg="#1e1e2e", fg="#cdd6f4",
            font=("Consolas", 9)
        ).pack(anchor="w", pady=(10, 0))

        # SHA256 — computed in background thread
        hash_var = tk.StringVar(value="SHA256:  computing…")
        tk.Label(
            frame, textvariable=hash_var, bg="#1e1e2e", fg="#cdd6f4",
            font=("Consolas", 9)
        ).pack(anchor="w", pady=(2, 0))

        def _compute_hash():
            try:
                sha256 = hashlib.sha256()
                with open(exe, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        sha256.update(chunk)
                h = sha256.hexdigest()
                win.after(0, lambda: hash_var.set(f"SHA256:  {h}"))
            except Exception as exc:
                win.after(0, lambda: hash_var.set(f"SHA256:  error — {exc}"))

        threading.Thread(target=_compute_hash, daemon=True).start()

        # Buttons
        btn_frame = tk.Frame(frame, bg="#1e1e2e")
        btn_frame.pack(fill="x", pady=(18, 0))

        lnk_style = {"font": ("Segoe UI", 9, "bold"), "cursor": "hand2", "relief": "flat", "bd": 0, "padx": 10, "pady": 4}

        query = urllib.parse.quote(f"{app_name} {os.path.basename(exe)}")
        tk.Button(
            btn_frame, text="🌐 Google", bg="#89b4fa", fg="#1e1e2e",
            command=lambda: webbrowser.open(f"https://www.google.com/search?q={query}"),
            **lnk_style
        ).pack(side="left", padx=(0, 8))

        vt_name = urllib.parse.quote(os.path.basename(exe))
        tk.Button(
            btn_frame, text="🦠 VirusTotal", bg="#fab387", fg="#1e1e2e",
            command=lambda: webbrowser.open(f"https://www.virustotal.com/gui/search/{vt_name}"),
            **lnk_style
        ).pack(side="left", padx=(0, 8))

        tk.Button(
            btn_frame, text="Close", bg="#45475a", fg="#cdd6f4",
            command=win.destroy, **lnk_style
        ).pack(side="left")

    def _decide(self, action: str):
        self.result = action
        exe = self.conn.exe_path
        name = self.conn.app_name

        # Save rule to database
        set_rule(self.db_conn, exe, name, action)

        # Apply to Windows Firewall
        sync_rule_to_firewall(exe, action)

        if self.on_decision:
            self.on_decision(exe, action)

        self._close()

    def _dismiss(self):
        self._close()

    def _auto_dismiss(self):
        if self.root.winfo_exists():
            self._close()

    def _close(self):
        if self in AlertPopup._active_popups:
            AlertPopup._active_popups.remove(self)
        try:
            self.root.destroy()
        except tk.TclError:
            pass

    def show(self):
        self.root.mainloop()


# ── Dashboard Window ──────────────────────────────────────────

class DashboardWindow:
    """Main dashboard showing live connections, rules, and history."""

    def __init__(self, db_conn, monitor: ConnectionMonitor):
        self.db_conn = db_conn
        self.monitor = monitor
        self.root = None
        self._visible = False

    def toggle(self):
        if self._visible:
            self.hide()
        else:
            self.show()

    def show(self):
        if self._visible and self.root:
            self.root.lift()
            return

        self.root = tk.Tk()
        self.root.title("Dimedropper — Network Monitor")
        self.root.geometry("1050x650")
        self.root.configure(bg="#1e1e2e")
        self.root.protocol("WM_DELETE_WINDOW", self.hide)
        self._visible = True

        self._build_ui()
        self._start_refresh()
        self.root.mainloop()

    def hide(self):
        self._visible = False
        if self.root:
            try:
                self.root.destroy()
            except tk.TclError:
                pass
            self.root = None

    def _build_ui(self):
        # Title bar
        header = tk.Frame(self.root, bg="#181825", height=50)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(
            header, text="🛡  Dimedropper", bg="#181825", fg="#89b4fa",
            font=("Segoe UI", 16, "bold")
        ).pack(side="left", padx=15, pady=10)

        admin_text = "⚡ Admin" if is_admin() else "⚠ Limited (run as Admin for firewall control)"
        admin_color = "#a6e3a1" if is_admin() else "#fab387"
        tk.Label(
            header, text=admin_text, bg="#181825", fg=admin_color,
            font=("Segoe UI", 9)
        ).pack(side="right", padx=15)

        # Notebook (tabs)
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background="#1e1e2e", borderwidth=0)
        style.configure("TNotebook.Tab", background="#313244", foreground="#cdd6f4",
                        padding=[15, 6], font=("Segoe UI", 10))
        style.map("TNotebook.Tab",
                  background=[("selected", "#45475a")],
                  foreground=[("selected", "#89b4fa")])

        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=10, pady=(5, 10))

        # Tab 1: Live Connections
        self.live_frame = tk.Frame(nb, bg="#1e1e2e")
        nb.add(self.live_frame, text="  Live Connections  ")
        self._build_live_tab()

        # Tab 2: Rules
        self.rules_frame = tk.Frame(nb, bg="#1e1e2e")
        nb.add(self.rules_frame, text="  Firewall Rules  ")
        self._build_rules_tab()

        # Tab 3: Connection History
        self.history_frame = tk.Frame(nb, bg="#1e1e2e")
        nb.add(self.history_frame, text="  History  ")
        self._build_history_tab()

    def _build_live_tab(self):
        # Summary bar
        self.live_summary = tk.Label(
            self.live_frame, text="Monitoring...", bg="#1e1e2e", fg="#a6adc8",
            font=("Segoe UI", 9), anchor="w"
        )
        self.live_summary.pack(fill="x", padx=5, pady=(8, 4))

        # Treeview
        cols = ("app", "pid", "remote", "port", "proto", "status")
        self.live_tree = ttk.Treeview(self.live_frame, columns=cols, show="headings", height=22)

        self.live_tree.heading("app", text="Application")
        self.live_tree.heading("pid", text="PID")
        self.live_tree.heading("remote", text="Remote Host")
        self.live_tree.heading("port", text="Port")
        self.live_tree.heading("proto", text="Proto")
        self.live_tree.heading("status", text="Status")

        self.live_tree.column("app", width=250)
        self.live_tree.column("pid", width=70)
        self.live_tree.column("remote", width=300)
        self.live_tree.column("port", width=70)
        self.live_tree.column("proto", width=60)
        self.live_tree.column("status", width=100)

        # Treeview styling
        style = ttk.Style()
        style.configure("Treeview",
                        background="#313244", foreground="#cdd6f4",
                        fieldbackground="#313244", borderwidth=0,
                        font=("Consolas", 9))
        style.configure("Treeview.Heading",
                        background="#45475a", foreground="#89b4fa",
                        font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", "#585b70")])

        scrollbar = ttk.Scrollbar(self.live_frame, orient="vertical", command=self.live_tree.yview)
        self.live_tree.configure(yscrollcommand=scrollbar.set)

        self.live_tree.pack(side="left", fill="both", expand=True, padx=(5, 0), pady=5)
        scrollbar.pack(side="right", fill="y", pady=5, padx=(0, 5))

        # Right-click context menu
        self.live_menu = tk.Menu(self.live_tree, tearoff=0, bg="#313244", fg="#cdd6f4")
        self.live_menu.add_command(label="🚫  Block this app", command=lambda: self._context_action("block"))
        self.live_menu.add_command(label="✅  Allow this app", command=lambda: self._context_action("allow"))
        self.live_menu.add_separator()
        self.live_menu.add_command(label="📋  Copy remote address", command=self._copy_remote)
        self.live_tree.bind("<Button-3>", self._show_context_menu)

    def _build_rules_tab(self):
        toolbar = tk.Frame(self.rules_frame, bg="#1e1e2e")
        toolbar.pack(fill="x", padx=5, pady=(8, 4))

        tk.Button(
            toolbar, text="↻ Refresh", bg="#45475a", fg="#cdd6f4",
            font=("Segoe UI", 9), relief="flat", command=self._refresh_rules
        ).pack(side="left", padx=(0, 5))

        tk.Button(
            toolbar, text="Remove Selected", bg="#f38ba8", fg="#1e1e2e",
            font=("Segoe UI", 9), relief="flat", command=self._remove_selected_rule
        ).pack(side="left")

        cols = ("app", "exe_path", "action", "updated")
        self.rules_tree = ttk.Treeview(self.rules_frame, columns=cols, show="headings", height=20)

        self.rules_tree.heading("app", text="Application")
        self.rules_tree.heading("exe_path", text="Executable Path")
        self.rules_tree.heading("action", text="Action")
        self.rules_tree.heading("updated", text="Last Updated")

        self.rules_tree.column("app", width=180)
        self.rules_tree.column("exe_path", width=400)
        self.rules_tree.column("action", width=80)
        self.rules_tree.column("updated", width=180)

        self.rules_tree.pack(fill="both", expand=True, padx=5, pady=5)

    def _build_history_tab(self):
        toolbar = tk.Frame(self.history_frame, bg="#1e1e2e")
        toolbar.pack(fill="x", padx=5, pady=(8, 4))

        tk.Button(
            toolbar, text="↻ Refresh", bg="#45475a", fg="#cdd6f4",
            font=("Segoe UI", 9), relief="flat", command=self._refresh_history
        ).pack(side="left", padx=(0, 5))

        tk.Label(toolbar, text="Filter app:", bg="#1e1e2e", fg="#a6adc8",
                 font=("Segoe UI", 9)).pack(side="left", padx=(10, 3))
        self.history_filter = tk.Entry(toolbar, width=30, bg="#313244", fg="#cdd6f4",
                                       insertbackground="#cdd6f4", font=("Consolas", 9))
        self.history_filter.pack(side="left")
        self.history_filter.bind("<Return>", lambda e: self._refresh_history())

        cols = ("time", "app", "remote", "port", "proto", "action")
        self.history_tree = ttk.Treeview(self.history_frame, columns=cols, show="headings", height=20)

        self.history_tree.heading("time", text="Time")
        self.history_tree.heading("app", text="Application")
        self.history_tree.heading("remote", text="Remote Host")
        self.history_tree.heading("port", text="Port")
        self.history_tree.heading("proto", text="Proto")
        self.history_tree.heading("action", text="Action")

        self.history_tree.column("time", width=160)
        self.history_tree.column("app", width=200)
        self.history_tree.column("remote", width=250)
        self.history_tree.column("port", width=70)
        self.history_tree.column("proto", width=60)
        self.history_tree.column("action", width=80)

        self.history_tree.pack(fill="both", expand=True, padx=5, pady=5)

    # ── Live tab refresh ──────────────────────────────────────

    def _start_refresh(self):
        if not self._visible or not self.root:
            return
        self._refresh_live()
        self._refresh_rules()
        self._refresh_history()
        if self.root:
            self.root.after(2000, self._start_refresh)

    def _refresh_live(self):
        try:
            conns = snapshot_connections()
        except Exception:
            return

        self.live_tree.delete(*self.live_tree.get_children())

        # Group by app for summary
        apps = defaultdict(int)
        for c in conns:
            name = c.app_name or os.path.basename(c.exe_path) or "Unknown"
            apps[name] += 1
            hostname = resolve(c.remote_addr)
            self.live_tree.insert("", "end", values=(
                name, c.pid, hostname, c.remote_port, c.protocol.upper(), c.status
            ))

        self.live_summary.config(
            text=f"{len(conns)} active connections across {len(apps)} applications"
        )

    def _refresh_rules(self):
        rules = get_all_rules(self.db_conn)
        self.rules_tree.delete(*self.rules_tree.get_children())
        for r in rules:
            ts = datetime.fromtimestamp(r["updated_at"]).strftime("%Y-%m-%d %H:%M:%S")
            action_display = "🚫 BLOCK" if r["action"] == "block" else "✅ ALLOW"
            self.rules_tree.insert("", "end", values=(
                r["app_name"] or "Unknown", r["exe_path"], action_display, ts
            ))

    def _refresh_history(self):
        filt = self.history_filter.get().strip() if hasattr(self, 'history_filter') else None
        logs = get_log(self.db_conn, limit=500, exe_filter=filt if filt else None)
        self.history_tree.delete(*self.history_tree.get_children())
        for entry in logs:
            ts = datetime.fromtimestamp(entry["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            self.history_tree.insert("", "end", values=(
                ts, entry["app_name"] or "Unknown",
                entry["remote_addr"], entry["remote_port"],
                entry["protocol"] or "", entry["action"] or ""
            ))

    # ── Context menu actions ──────────────────────────────────

    def _show_context_menu(self, event):
        item = self.live_tree.identify_row(event.y)
        if item:
            self.live_tree.selection_set(item)
            self.live_menu.post(event.x_root, event.y_root)

    def _get_selected_live_exe(self) -> tuple[str, str] | None:
        """Return (app_name, exe_path) from live tree selection."""
        sel = self.live_tree.selection()
        if not sel:
            return None
        vals = self.live_tree.item(sel[0], "values")
        # We need the exe_path — find it from current connections
        app_name = vals[0]
        pid = int(vals[1])
        try:
            import psutil
            proc = psutil.Process(pid)
            return app_name, proc.exe()
        except Exception:
            return app_name, ""

    def _context_action(self, action: str):
        info = self._get_selected_live_exe()
        if not info or not info[1]:
            messagebox.showwarning("Dimedropper", "Could not determine executable path.")
            return
        app_name, exe_path = info
        set_rule(self.db_conn, exe_path, app_name, action)
        sync_rule_to_firewall(exe_path, action)
        verb = "blocked" if action == "block" else "allowed"
        messagebox.showinfo("Dimedropper", f"{app_name} has been {verb}.")
        self._refresh_rules()

    def _copy_remote(self):
        sel = self.live_tree.selection()
        if sel:
            vals = self.live_tree.item(sel[0], "values")
            self.root.clipboard_clear()
            self.root.clipboard_append(f"{vals[2]}:{vals[3]}")

    def _remove_selected_rule(self):
        sel = self.rules_tree.selection()
        if not sel:
            return
        exe_path = self.rules_tree.item(sel[0], "values")[1]
        delete_rule(self.db_conn, exe_path)
        remove_rule(exe_path)
        self._refresh_rules()


# ── Application Controller ────────────────────────────────────

class DimedropperApp:
    """Top-level controller: wires together monitor, database, tray icon, and dashboard."""

    def __init__(self):
        self.db_conn = get_connection()
        init_db(self.db_conn)
        self.monitor = ConnectionMonitor()
        self.dashboard = DashboardWindow(self.db_conn, self.monitor)
        self._tray_icon = None
        self._alert_queue: list[ConnectionInfo] = []
        self._alert_lock = threading.Lock()

    def run(self):
        # Register monitor callbacks
        self.monitor.on_new_connection(self._on_new_connection)

        # Start monitoring
        self.monitor.start()
        logger.info("Dimedropper started")

        # Start the alert consumer thread
        self._alert_thread = threading.Thread(target=self._alert_consumer, daemon=True)
        self._alert_thread.start()

        if pystray and Image:
            self._run_tray()
        else:
            # Fallback: no tray, just open dashboard directly
            logger.warning("pystray/Pillow not installed — opening dashboard directly")
            self.dashboard.show()

    def _run_tray(self):
        icon_image = _create_icon_image()
        menu = pystray.Menu(
            pystray.MenuItem("Open Dashboard", self._open_dashboard, default=True),
            pystray.MenuItem("Pause Monitoring", self._toggle_monitoring),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", self._quit),
        )
        self._tray_icon = pystray.Icon("Dimedropper", icon_image, "Dimedropper", menu)
        self._tray_icon.run()

    def _on_new_connection(self, conn: ConnectionInfo):
        """Called from the monitor thread when a new app→remote pair is detected."""
        # Log to database
        if LOG_ALL_CONNECTIONS:
            rule = get_rule(self.db_conn, conn.exe_path)
            action = rule["action"] if rule else "unknown"
            log_connection(
                self.db_conn,
                pid=conn.pid, exe_path=conn.exe_path, app_name=conn.app_name,
                local_addr=conn.local_addr, local_port=conn.local_port,
                remote_addr=conn.remote_addr, remote_port=conn.remote_port,
                protocol=conn.protocol, status=conn.status, action=action,
            )

        # Check if this app already has a rule
        rule = get_rule(self.db_conn, conn.exe_path)
        if rule:
            return  # Already decided — no alert needed

        # Check if this is a brand-new app
        is_new = record_first_seen(self.db_conn, conn.exe_path, conn.app_name)

        if ALERT_NEW_APPS and is_new:
            with self._alert_lock:
                self._alert_queue.append(conn)
        elif ALERT_UNKNOWN_APPS and not rule:
            with self._alert_lock:
                # Only alert once per exe per session
                existing_exes = {c.exe_path for c in self._alert_queue}
                if conn.exe_path not in existing_exes:
                    self._alert_queue.append(conn)

    def _alert_consumer(self):
        """Process alert popups one at a time in a tkinter-compatible way."""
        while True:
            conn = None
            with self._alert_lock:
                if self._alert_queue:
                    conn = self._alert_queue.pop(0)

            if conn:
                try:
                    popup = AlertPopup(conn, self.db_conn, on_decision=self._on_rule_decision)
                    popup.show()
                except Exception:
                    logger.exception("Error showing alert popup")
            else:
                time.sleep(0.5)

    def _on_rule_decision(self, exe_path: str, action: str):
        logger.info("Rule set: %s → %s", exe_path, action)

    def _open_dashboard(self, icon=None, item=None):
        t = threading.Thread(target=self.dashboard.show, daemon=True)
        t.start()

    def _toggle_monitoring(self, icon, item):
        if self.monitor._running:
            self.monitor.stop()
            logger.info("Monitoring paused")
        else:
            self.monitor.start()
            logger.info("Monitoring resumed")

    def _quit(self, icon, item):
        self.monitor.stop()
        if self._tray_icon:
            self._tray_icon.stop()
        os._exit(0)
