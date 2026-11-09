"""msf_advisor.py — live Metasploit RPC advisor.

Wakes msfrpcd inside the Kali tool container (on demand), then answers:
  - search_exploits("CVE-2021-44228")  → matching exploit modules
  - search_exploits("smb eternalblue") → keyword module search
  - resource_script(...)               → .rc content
  - prepare_terminal(...)              → rc written in container +
                                         msfconsole -q -r <rc> command

The rc file is written INSIDE kali-as; the returned command is meant to
be pre-filled in a tmux session (operator presses Enter).
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AttackSurface.MSFAdvisor")

KALI_CONTAINER = os.environ.get("KALI_CONTAINER", "kali-as")
RPC_PORT = int(os.environ.get("MSF_PORT", "55553"))
_RANK_LABEL = {0: "low", 100: "average", 200: "manual", 300: "normal",
               400: "good", 500: "great", 600: "excellent"}

_state = {"client": None, "host": None, "pass": None, "ready": False}


def _write_env(user: str, password: str, host: str, port: int) -> None:
    envf = os.path.expanduser("~/.attack_surface/msfrpcd.env")
    try:
        os.makedirs(os.path.dirname(envf), exist_ok=True)
        with open(envf, "w") as f:
            f.write(f"MSF_USER={user}\nMSF_RPC_PASS={password}\n"
                    f"MSF_HOST={host}\nMSF_PORT={port}\n")
        os.chmod(envf, 0o600)
    except Exception as e:
        logger.debug("could not write msfrpcd.env: %s", e)


def _container_ip() -> str:
    try:
        r = subprocess.run(
            ["docker", "inspect", KALI_CONTAINER],
            capture_output=True, text=True, timeout=15)
        import json as _json
        data = _json.loads(r.stdout or "[]")
        nets = (data[0].get("NetworkSettings") or {}).get("Networks") or {}
        for net in nets.values():
            ip = net.get("IPAddress") or ""
            if ip:
                return ip
    except Exception:
        pass
    return ""


def _rpc_reachable(host: str, port: int) -> bool:
    import socket
    try:
        with socket.create_connection((host, port), timeout=4):
            return True
    except Exception:
        return False


def ensure_rpcd() -> Dict[str, Any]:
    """Make msfrpcd reachable; start (or restart) it in kali-as if needed.

    Returns {ok, host, port, started, error?}.
    """
    import json as _json

    if _state["ready"] and _state["host"] and _rpc_reachable(_state["host"], RPC_PORT):
        return {"ok": True, "host": _state["host"], "port": RPC_PORT, "started": False}

    ip = _container_ip()
    if not ip:
        return {"ok": False, "error": "kali-as container not running or has no IP"}

    # msfrpcd already listening? try connecting with current creds
    if _rpc_reachable(ip, RPC_PORT):
        client = _client()
        if client is not None:
            _state.update(host=ip, ready=True)
            return {"ok": True, "host": ip, "port": RPC_PORT, "started": False}
        # reachable but auth failed (stale process with unknown password/SSL)
        # → kill it and start fresh with our own credentials
        try:
            subprocess.run(["docker", "exec", KALI_CONTAINER, "pkill", "-f", "msfrpcd"],
                           capture_output=True, timeout=15)
            time.sleep(1.5)
        except Exception:
            pass

    # start msfrpcd inside kali-as (SSL on, bind 0.0.0.0 → reachable via container IP)
    import secrets
    password = os.environ.get("MSF_RPC_PASS") or secrets.token_hex(12)
    user = os.environ.get("MSF_USER", "msf")
    try:
        subprocess.run(
            ["docker", "exec", "-d", KALI_CONTAINER, "msfrpcd",
             "-U", user, "-P", password, "-p", str(RPC_PORT),
             "-a", "0.0.0.0", "-n"],
            capture_output=True, timeout=20)
    except Exception as e:
        return {"ok": False, "error": f"could not start msfrpcd: {e}"}

    for _ in range(12):
        time.sleep(1.0)
        if not _rpc_reachable(ip, RPC_PORT):
            continue
        _state.update(host=ip, pass_=None, ready=False)
        _state["pass"] = password
        client = _client()
        if client is not None:
            _write_env(user, password, ip, RPC_PORT)
            _state["ready"] = True
            return {"ok": True, "host": ip, "port": RPC_PORT, "started": True}
    return {"ok": False, "error": "msfrpcd did not become reachable/authenticated"}


def _client():
    """Lazy MSFRPCClient wired to the live msfrpcd instance."""
    if _state["client"] is not None:
        return _state["client"]
    from modules.redteam.metasploit import MSFRPCClient
    from modules.redteam.config import MetasploitConfig
    cfg = MetasploitConfig(
        host=_state["host"] or "127.0.0.1", port=RPC_PORT,
        user=os.environ.get("MSF_USER", "msf"),
        password=_state.get("pass") or os.environ.get("MSF_RPC_PASS", ""),
        ssl=True)
    client = MSFRPCClient(cfg)
    res = client.connect()
    if not res.get("success"):
        logger.warning("msfrpcd connect failed: %s", res.get("error"))
        return None
    _state["client"] = client
    return client


def _mod_dict(m) -> Dict[str, Any]:
    return {
        "name": getattr(m, "fullname", "") or getattr(m, "name", ""),
        "type": getattr(m, "type", ""),
        "rank": getattr(m, "rank", 0),
        "rank_label": _RANK_LABEL.get(getattr(m, "rank", 0), "n/a"),
        "description": (getattr(m, "description", "") or "")[:220],
        "references": list(getattr(m, "references", []) or [])[:5],
    }


def search_exploits(query: str) -> Dict[str, Any]:
    """Search msfrpcd for exploit modules. CVE-YYYY-NNNN → CVE match."""
    q = (query or "").strip()
    if not q:
        return {"ok": False, "error": "empty query"}
    st = ensure_rpcd()
    if not st.get("ok"):
        return {"ok": False, "error": st.get("error", "msfrpcd unavailable")}
    client = _client()
    if client is None:
        return {"ok": False, "error": "msfrpcd connect failed"}
    try:
        if re.match(r"(?i)cve-\d{4}-\d+", q):
            mods = client.module_exploit_matching_cve(q.upper())
        else:
            mods = [m for m in client.module_search(q) if m.type == "exploit"]
        mods = sorted(mods, key=lambda m: -getattr(m, "rank", 0))[:20]
        return {"ok": True, "query": q, "rpc_host": st.get("host"),
                "modules": [_mod_dict(m) for m in mods]}
    except Exception as e:
        return {"ok": False, "error": f"msfrpcd search failed: {e}"}


def resource_script(module: str, target: str,
                    payload: str = "", lhost: str = "") -> str:
    """msfconsole resource script: use → RHOSTS → (PAYLOAD/LHOST) → exploit -j."""
    from modules.redteam import msf_map
    lhost = lhost or msf_map.auto_lhost()
    lines = [f"use {module}", f"set RHOSTS {target}"]
    if payload:
        lines.append(f"set PAYLOAD {payload}")
    if lhost:
        lines.append(f"set LHOST {lhost}")
    lines.append("exploit -j")
    return "\n".join(lines) + "\n"


def prepare_terminal(module: str, target: str,
                     payload: str = "", lhost: str = "") -> Dict[str, Any]:
    """Write the rc inside kali-as + build the pre-fill command.

    Returns {ok, cmd, rc_path, module, target, error?}.
    """
    if not module or not target:
        return {"ok": False, "error": "module and target are required"}
    if not re.match(r"^[a-z0-9_/.-]+$", module, re.IGNORECASE):
        return {"ok": False, "error": "invalid module name"}
    if re.search(r"[\s;`$|><]", target):
        return {"ok": False, "error": "invalid target"}

    rc = resource_script(module, target, payload, lhost)
    rc_path = f"/tmp/as_msf_{abs(hash((module, target))) % 10**8}.rc"
    try:
        subprocess.run(
            ["docker", "exec", KALI_CONTAINER, "bash", "-c",
             f"cat > {rc_path} << 'AS_EOF'\n{rc}AS_EOF"],
            capture_output=True, timeout=20, check=True)
    except Exception as e:
        return {"ok": False, "error": f"could not write rc in container: {e}"}
    return {"ok": True, "cmd": f"msfconsole -q -r {rc_path}",
            "rc_path": rc_path, "module": module, "target": target,
            "rc_preview": rc.strip()}
