This was totally vibecoded so it's probably a big old vulnerability. Use at own risk.
# 🛡 NetGuard — Network Monitor for Windows

A lightweight "Little Snitch for Windows" — monitors every outbound network connection, alerts you when new apps phone home, and lets you block or allow them through Windows Firewall with one click.

## Features

- **Real-time connection monitoring** — See every active TCP/UDP connection mapped to its process, with reverse DNS resolution
- **Popup alerts** — Toast-style notifications when a never-before-seen app makes an outbound connection
- **One-click firewall rules** — Allow or block any app directly from the alert popup or dashboard (creates Windows Firewall outbound rules via `netsh`)
- **System tray** — Runs quietly in the background; double-click the shield icon to open the dashboard
- **Connection history** — All connections logged to a local SQLite database with filtering
- **Rule management** — View, add, and remove firewall rules from the dashboard
- **CLI mode** — Print live connections to the terminal for quick inspection

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run as Administrator (required for firewall control)
#    Right-click Command Prompt → "Run as Administrator"
python main.py
```

### Launch Modes

| Command | Description |
|---------|-------------|
| `python main.py` | System tray mode (default) — runs in background |
| `python main.py --dashboard` | Opens the dashboard window directly |
| `python main.py --cli` | Terminal-only — prints live connections to stdout |

## How It Works

### Monitoring
Uses `psutil` to poll active TCP/UDP connections every second, mapping each to its owning process. New app→remote endpoint pairs trigger alert callbacks.

### Alerts
When an app connects to the internet for the first time, a popup appears with:
- App name and executable path
- Remote host (with async reverse DNS)
- **Allow** / **Block** / **Dismiss** buttons

Your decision is saved permanently — NetGuard won't ask about the same app again.

### Firewall Integration
When you Allow or Block an app, NetGuard creates a Windows Firewall outbound rule via:
```
netsh advfirewall firewall add rule name=NetGuard_app.exe dir=out action=block program=C:\path\to\app.exe
```
All NetGuard rules are prefixed with `NetGuard_` so they're easy to identify and clean up.

### Data Storage
Everything is stored in `~/.netguard/netguard.db` (SQLite):
- **rules** — Your allow/block decisions
- **connection_log** — Full history of observed connections
- **first_seen** — Tracks when each app was first detected

## Dashboard

The dashboard has three tabs:

1. **Live Connections** — Real-time view of all active connections. Right-click any row to block/allow the app.
2. **Firewall Rules** — All your saved rules with the ability to remove them.
3. **History** — Searchable log of all past connections with timestamps.

## Requirements

- **Windows 10/11**
- **Python 3.10+**
- **Administrator privileges** for firewall rule management (monitoring works without admin, but you'll get a warning)
- `psutil`, `pystray`, `Pillow` (see requirements.txt)

## Architecture

```
netguard/
├── main.py          Entry point — CLI arg parsing, dependency check
├── app.py           NetGuardApp controller, tray icon, alert popups, dashboard UI
├── monitor.py       Connection polling via psutil, new-connection detection
├── firewall.py      Windows Firewall management via netsh advfirewall
├── database.py      SQLite schema, rule/log CRUD operations
├── resolver.py      Async reverse DNS lookup with caching
└── requirements.txt
```

## Notes & Limitations

- **Polling-based**: Connections are detected by polling (`psutil.net_connections()`), not kernel-level packet interception. Very short-lived connections might be missed. A future version could use ETW (Event Tracing for Windows) for event-driven detection.
- **Process-level granularity**: Rules apply to entire executables, not per-domain or per-port (same as Little Snitch's default behavior).
- **No driver needed**: Unlike commercial tools (GlassWire, Portmaster), this uses the built-in Windows Firewall rather than a custom WFP driver, which means zero risk of BSODs and no kernel components to install.
