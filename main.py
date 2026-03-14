"""
NetGuard — Little Snitch for Windows
Entry point. Run as Administrator for full firewall control.

Usage:
    python main.py              Launch with system tray
    python main.py --dashboard  Launch dashboard directly (no tray)
    python main.py --cli        Print live connections to terminal
"""

import sys
import os
import logging

# Add the project dir to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("netguard")


def check_dependencies():
    """Verify required packages are installed."""
    missing = []
    try:
        import psutil
    except ImportError:
        missing.append("psutil")
    try:
        import pystray
    except ImportError:
        missing.append("pystray")
    try:
        from PIL import Image
    except ImportError:
        missing.append("Pillow")

    if missing:
        print("=" * 55)
        print("  NetGuard — Missing Dependencies")
        print("=" * 55)
        print()
        print("  Install them with:")
        print(f"    pip install {' '.join(missing)}")
        print()
        if "psutil" in missing:
            print("  ⚠ psutil is required — cannot run without it.")
            sys.exit(1)
        else:
            print("  ⚠ pystray/Pillow missing — tray icon disabled.")
            print("    Dashboard will open directly instead.")
            print()


def run_cli():
    """Simple CLI mode — print connections to stdout."""
    import time
    from monitor import snapshot_connections
    from resolver import resolve

    print("NetGuard CLI — Live Connections (Ctrl+C to stop)")
    print("-" * 90)
    print(f"{'Application':<25} {'PID':<8} {'Remote Host':<35} {'Port':<7} {'Proto':<6} {'Status'}")
    print("-" * 90)

    seen = set()
    try:
        while True:
            conns = snapshot_connections()
            for c in conns:
                key = c.key
                if key not in seen:
                    seen.add(key)
                    host = resolve(c.remote_addr)
                    name = (c.app_name or "?")[:24]
                    print(f"{name:<25} {c.pid:<8} {host:<35} {c.remote_port:<7} {c.protocol.upper():<6} {c.status}")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopped.")


def main():
    check_dependencies()

    if "--cli" in sys.argv:
        run_cli()
        return

    from app import NetGuardApp
    from firewall import is_admin

    if not is_admin():
        logger.warning(
            "Not running as Administrator — firewall blocking/allowing will fail. "
            "Right-click → Run as Administrator for full functionality."
        )

    app = NetGuardApp()

    if "--dashboard" in sys.argv:
        # Skip tray, open dashboard directly
        app.monitor.start()
        app.dashboard.show()
    else:
        app.run()


if __name__ == "__main__":
    main()
