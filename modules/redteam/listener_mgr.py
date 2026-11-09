"""listener_mgr.py — Phase 1: Listener / C2 management.

Starts and manages attack listeners inside the Kali tool container:
  - msfrpcd  : Metasploit RPC daemon (exploit handler backend)
  - sliver   : Sliver C2 gRPC server

Everything is operator-gated: listeners start on explicit request,
credentials are rotated per-boot, and all state is audit-logged.
"""
from __future__ import annotations

import logging
import os
import re
import secrets
import subprocess
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("AttackSurface.ListenerMgr")

KALI_CONTAINER = os.environ.get("KALI_CONTAINER", "kali-as")
STATE_DIR = os.path.expanduser("~/.attack_surface")


def _docker(args: list, timeout: int = 20, input_data: str = ""):
    return subprocess.run(
        ["docker", "exec", "-i", KALI_CONTAINER] + args,
        capture_output=True, text=True, timeout=timeout, input=input_data)


def _write_env(keyvals: Dict[str, str]) -> str:
    os.makedirs(STATE_DIR, exist_ok=True)
    path = os.path.join(STATE_DIR, "killchain.env")
    existing = {}
    if os.path.isfile(path):
        for line in open(path):
            if "=" in line and not line.strip().startswith("#"):
                k, _, v = line.partition("=")
                existing[k.strip()] = v.strip()
    existing.update(keyvals)
    with open(path, "w") as f:
        for k, v in existing.items():
            f.write(f"{k}={v}\n")
    os.chmod(path, 0o600)
    return path


def start_msf_listener(bind: str = "0.0.0.0", port: int = 55553,
                      user: str = "", password: str = "") -> Dict[str, Any]:
    """Start msfrpcd in kali-as. Returns {ok, user, password, port, already?}."""
    user = user or "msf"
    password = password or secrets.token_hex(12)
    # already running?
    chk = _docker(["bash", "-c", "pgrep -f msfrpcd >/dev/null && echo YES || echo NO"])
    if "YES" in (chk.stdout or ""):
        logger.info("msfrpcd already running")
        return {"ok": True, "already": True, "port": port,
                "note": "msfrpcd already running (credentials in msfrpcd.env)"}
    r = _docker(["msfrpcd", "-U", user, "-P", password,
                 "-p", str(port), "-a", bind, "-n"])
    time.sleep(1.5)
    chk = _docker(["bash", "-c", "pgrep -f msfrpcd >/dev/null && echo YES || echo NO"])
    alive = "YES" in (chk.stdout or "")
    if alive:
        _write_env({"MSF_USER": user, "MSF_RPC_PASS": password,
                    "MSF_PORT": str(port)})
        logger.info("msfrpcd started on %s:%s", bind, port)
        return {"ok": True, "user": user, "password": password, "port": port}
    return {"ok": False, "error": (r.stderr or "msfrpcd failed to start")[:200]}


def start_sliver_listener(bind: str = "0.0.0.0", port: int = 50051,
                         mtls: bool = True) -> Dict[str, Any]:
    """Start sliver-server daemon in kali-as. Returns {ok, port, profile}."""
    chk = _docker(["bash", "-c", "pgrep -f sliver-server >/dev/null && echo YES || echo NO"])
    if "YES" in (chk.stdout or ""):
        return {"ok": True, "already": True, "port": port}
    profile = "mtls" if mtls else "http"
    r = _docker(["sliver-server", "daemon",
                 "-l", f"{bind}:{port}"], timeout=30)
    time.sleep(2.0)
    chk = _docker(["bash", "-c", "pgrep -f sliver-server >/dev/null && echo YES || echo NO"])
    if "YES" in (chk.stdout or ""):
        _write_env({"SLIVER_PORT": str(port), "SLIVER_PROFILE": profile})
        logger.info("sliver server started on %s:%s (%s)", bind, port, profile)
        return {"ok": True, "port": port, "profile": profile}
    return {"ok": False, "error": (r.stderr or "sliver failed to start")[:200]}


def listener_status() -> Dict[str, Any]:
    """Report state of both listeners."""
    msf_chk = _docker(["bash", "-c", "pgrep -f msfrpcd >/dev/null && echo YES || echo NO"])
    slv_chk = _docker(["bash", "-c", "pgrep -f sliver-server >/dev/null && echo YES || echo NO"])
    env = {}
    envf = os.path.join(STATE_DIR, "killchain.env")
    if os.path.isfile(envf):
        for line in open(envf):
            if "=" in line and not line.strip().startswith("#"):
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip()
    return {
        "msfrpcd": "YES" in (msf_chk.stdout or ""),
        "sliver": "YES" in (slv_chk.stdout or ""),
        "msf_port": env.get("MSF_PORT", "55553"),
        "sliver_port": env.get("SLIVER_PORT", "50051"),
        "msf_user": env.get("MSF_USER", "msf"),
    }


def stop_listeners() -> Dict[str, Any]:
    """Stop both listeners (operator-initiated only)."""
    _docker(["bash", "-c", "pkill -f msfrpcd || true"])
    _docker(["bash", "-c", "pkill -f sliver-server || true"])
    time.sleep(1.0)
    return listener_status()
