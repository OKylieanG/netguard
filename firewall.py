"""
NetGuard — Windows Firewall integration
Creates/removes outbound firewall rules using `netsh advfirewall`.
Requires Administrator privileges.
"""

import subprocess
import logging
import ctypes
import os
import sys

logger = logging.getLogger("netguard.firewall")

RULE_PREFIX = "NetGuard_"  # Prefix for all rules we create, so we can track them


def is_admin() -> bool:
    """Check if the current process has admin privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        # Not on Windows
        return False


def request_admin_restart():
    """Relaunch the current script with admin privileges (UAC prompt)."""
    if is_admin():
        return True
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit(0)
    except Exception:
        logger.exception("Failed to elevate privileges")
        return False


def _rule_name(exe_path: str) -> str:
    """Generate a deterministic rule name from an exe path."""
    safe = os.path.basename(exe_path).replace(" ", "_")
    return f"{RULE_PREFIX}{safe}"


def _run_netsh(args: list[str], check=True) -> subprocess.CompletedProcess:
    """Run a netsh command and return the result."""
    cmd = ["netsh"] + args
    logger.debug("Running: %s", " ".join(cmd))
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
    )
    if check and result.returncode != 0:
        logger.error("netsh failed: %s", result.stderr.strip() or result.stdout.strip())
    return result


def block_app(exe_path: str) -> bool:
    """
    Create an outbound block rule for the given executable.
    Returns True on success.
    """
    if not exe_path:
        return False

    name = _rule_name(exe_path)

    # Remove any existing rule first (idempotent)
    _remove_rule(name)

    result = _run_netsh([
        "advfirewall", "firewall", "add", "rule",
        f"name={name}",
        "dir=out",
        "action=block",
        f"program={exe_path}",
        "enable=yes",
        f"description=Blocked by NetGuard",
    ])
    success = result.returncode == 0
    if success:
        logger.info("Blocked: %s", exe_path)
    return success


def allow_app(exe_path: str) -> bool:
    """
    Create an outbound allow rule for the given executable.
    Returns True on success.
    """
    if not exe_path:
        return False

    name = _rule_name(exe_path)

    # Remove any existing rule first
    _remove_rule(name)

    result = _run_netsh([
        "advfirewall", "firewall", "add", "rule",
        f"name={name}",
        "dir=out",
        "action=allow",
        f"program={exe_path}",
        "enable=yes",
        f"description=Allowed by NetGuard",
    ])
    success = result.returncode == 0
    if success:
        logger.info("Allowed: %s", exe_path)
    return success


def remove_rule(exe_path: str) -> bool:
    """Remove any NetGuard rule for the given executable."""
    name = _rule_name(exe_path)
    return _remove_rule(name)


def _remove_rule(name: str) -> bool:
    result = _run_netsh([
        "advfirewall", "firewall", "delete", "rule",
        f"name={name}",
    ], check=False)
    return result.returncode == 0


def list_netguard_rules() -> list[dict]:
    """List all firewall rules created by NetGuard."""
    result = _run_netsh([
        "advfirewall", "firewall", "show", "rule",
        f"name=all", "dir=out", "verbose",
    ], check=False)

    rules = []
    current: dict = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            if current and current.get("name", "").startswith(RULE_PREFIX):
                rules.append(current)
            current = {}
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            current[key.strip().lower()] = val.strip()

    # Catch last entry
    if current and current.get("name", "").startswith(RULE_PREFIX):
        rules.append(current)

    return rules


def sync_rule_to_firewall(exe_path: str, action: str) -> bool:
    """
    Ensure the Windows Firewall matches the desired action.
    action: 'allow', 'block', or 'remove'
    """
    if action == "block":
        return block_app(exe_path)
    elif action == "allow":
        return allow_app(exe_path)
    elif action == "remove":
        return remove_rule(exe_path)
    return False
