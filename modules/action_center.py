"""action_center.py — operator-gated attack tool execution + terminal launch.

Flow A — background job (dashboard "Run"):
  1. POST /api/action  {action_id, tool, cmd, target}
     -> command is queued in PENDING (not run yet)
  2. POST /api/action/confirm {action_id, approved: true}
     -> subprocess runs, output streams to results
  3. GET /api/action/status?id=  -> poll output

Flow B — interactive terminal (dashboard "🖥 Terminal"), the PRIMARY flow:
  POST /api/action/terminal {tool, cmd, target, finding}
     -> validates against the whitelist
     -> creates a tmux session inside the Kali tool container with the
        attack command PRE-FILLED but NOT executed (operator reviews,
        edits if needed, presses Enter)
     -> returns the attach command; if the dashboard host has a display,
        a local terminal emulator is opened automatically.

Safety rails:
  - Whitelist of tools only (kali binaries), never raw shell.
  - Command template comes from auto_hunt mapping / attack chain, NOT
    user text; user may only pick among proposed commands.
  - Every action logged to ~/.attack_surface/audit.log.
  - Hard per-run timeout (600s default).
  - Tools execute inside the Kali container (KALI_CONTAINER env,
    default kali-as) — the environment where they are installed.
"""
from __future__ import annotations

import logging
import os
import re
import shlex
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List

AUDIT = Path(os.path.expanduser("~/.attack_surface/audit.log"))
MAX_TIMEOUT = 600
KALI_CONTAINER = os.environ.get("KALI_CONTAINER", "kali-as")

# tool -> binary name (local PATH or inside the Kali container)
TOOL_WHITELIST = {
    "sqlmap": "sqlmap", "wpscan": "wpscan", "nuclei": "nuclei",
    "nikto": "nikto", "hydra": "hydra", "dalfox": "dalfox",
    "subzy": "subzy", "testssl.sh": "testssl.sh", "nmap": "nmap",
    "dig": "dig", "curl": "curl", "git-dumper": "git-dumper",
    # Red Team tools (executed in Kali container via docker exec)
    "impacket-GetUserSPNs": "GetUserSPNs.py",
    "impacket-GetNPUsers": "GetNPUsers.py",
    "impacket-ntlmrelayx": "ntlmrelayx.py",
    "impacket-secretsdump": "secretsdump.py",
    "impacket-psexec": "psexec.py",
    "impacket-wmiexec": "wmiexec.py",
    "impacket-smbexec": "smbexec.py",
    "impacket-atexec": "atexec.py",
    "crackmapexec": "crackmapexec", "bloodhound-python": "bloodhound-python",
    "metasploit": "msfconsole", "pacu": "pacu", "cloudfox": "cloudfox",
    "sliver": "sliver-server", "ssh": "ssh",
}

# Tools whose natural home is the Kali container (red-team / pentest kit)
CONTAINER_TOOLS = set(TOOL_WHITELIST) - {"dig", "curl", "ssh"}

_LOCK = threading.Lock()
_JOBS: Dict[str, Dict[str, Any]] = {}   # id -> {cmd, tool, target, status, output[], rc, started}
PENDING: Dict[str, Dict[str, Any]] = {} # awaiting operator approval


def _audit(msg: str) -> None:
    try:
        AUDIT.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except Exception:
        pass


def _kali_which(binary: str) -> bool:
    """True if `binary` exists inside the Kali tool container."""
    try:
        r = subprocess.run(["docker", "exec", KALI_CONTAINER, "which", binary],
                           capture_output=True, timeout=15)
        return r.returncode == 0
    except Exception:
        return False


def _runner_for(tool: str) -> str | None:
    """Where this tool can run: 'local', 'container', or None (unavailable)."""
    binary = TOOL_WHITELIST.get(tool)
    if not binary:
        return None
    if shutil.which(binary):
        return "local"
    if tool in CONTAINER_TOOLS and _kali_which(binary):
        return "container"
    return None


def propose(tool: str, cmd: str, target: str, finding: str = "",
            meta: Dict[str, Any] | None = None) -> Dict[str, Any] | None:
    """Validate + queue an action awaiting operator approval."""
    binary = TOOL_WHITELIST.get(tool)
    if not binary or not cmd.strip():
        return None
    runner = _runner_for(tool)
    if runner is None:
        return None
    if runner == "local" and not cmd.lstrip().startswith(binary):
        return None  # local commands must start with the whitelisted binary

    action_id = uuid.uuid4().hex[:10]
    with _LOCK:
        PENDING[action_id] = {
            "id": action_id, "tool": tool, "cmd": cmd,
            "target": target, "finding": finding[:120],
            "ts": time.time(), "runner": runner,
            "meta": meta or {},
        }
    _audit(f"PROPOSE {action_id} tool={tool} target={target} runner={runner} cmd={cmd[:150]}")
    return PENDING[action_id]


def approve(action_id: str, approved: bool) -> bool:
    """Operator decision. If approved, launch the job."""
    with _LOCK:
        act = PENDING.pop(action_id, None)
    if not act:
        return False
    if not approved:
        _audit(f"REJECT {action_id} cmd={act['cmd'][:150]}")
        return False
    job_id = action_id
    job = {
        "id": job_id, "tool": act["tool"], "cmd": act["cmd"],
        "target": act["target"], "status": "running",
        "runner": act.get("runner", "local"),
        "meta": act.get("meta") or {},
        "output": [], "rc": None, "started": time.time(),
    }
    with _LOCK:
        _JOBS[job_id] = job
    _audit(f"APPROVE {action_id} cmd={act['cmd'][:150]}")
    threading.Thread(target=_run, args=(job,), daemon=True).start()
    return True


def _run(job: Dict[str, Any]) -> None:
    try:
        if job.get("runner") == "container":
            # shlex.split keeps quoted args (wordlists, passwords with spaces)
            cmd = ["docker", "exec", "-i", KALI_CONTAINER] + shlex.split(job["cmd"])
            shell = False
        else:
            cmd = job["cmd"]
            shell = True

        proc = subprocess.Popen(
            cmd, shell=shell,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1)
        timer = threading.Timer(MAX_TIMEOUT, proc.kill)
        timer.daemon = True
        timer.start()
        for line in proc.stdout:
            with _LOCK:
                job["output"].append(line.rstrip()[:400])
                job["output"] = job["output"][-400:]
        rc = proc.wait()
        timer.cancel()
        job["rc"] = rc
        job["status"] = "done" if rc == 0 else f"exit {rc}"
    except Exception as e:
        job["status"] = f"error: {e}"
        job["rc"] = -1
    _audit(f"FINISH {job['id']} rc={job['rc']}")
    # Auto CHECK→EXPLOIT loop: confirmed vulns get a second pre-filled
    # terminal session (exploit + payload + LHOST) + telegram alert.
    if job.get("tool") == "metasploit":
        try:
            from modules.redteam import auto_exploit
            auto_exploit.maybe_chain_exploit(job, open_terminal)
            if job.get("auto_exploit"):
                _audit(f"AUTO-CHAIN {job['id']} -> {job['auto_exploit'].get('module')}")
        except Exception as e:
            logging.getLogger("AttackSurface.ActionCenter").warning(
                "auto-exploit hook failed: %s", e)


def status(job_id: str) -> Dict[str, Any] | None:
    with _LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return None
        return {"id": job["id"], "tool": job["tool"], "cmd": job["cmd"],
                "status": job["status"], "rc": job["rc"],
                "output": job["output"][-80:],
                "elapsed": round(time.time() - job["started"], 1)}


def list_jobs() -> List[Dict[str, Any]]:
    with _LOCK:
        return [{"id": j["id"], "tool": j["tool"], "target": j["target"],
                 "status": j["status"], "cmd": j["cmd"]}
                for j in _JOBS.values()]


def list_pending() -> List[Dict[str, Any]]:
    with _LOCK:
        return list(PENDING.values())


def tool_available(tool: str) -> bool:
    return _runner_for(tool) is not None


# ---------------------------------------------------------------------------
# Terminal launch — the operator flow the scanner is built around:
#   finding → red-team attack option → TERMINAL opens with the exact
#   attack command pre-filled (e.g. brute force → hydra line ready to go).
# ---------------------------------------------------------------------------

def _spawn_local_terminal(attach_cmd: str) -> bool:
    """Best-effort: open a local terminal emulator running the attach cmd."""
    if not os.environ.get("DISPLAY"):
        return False
    if os.environ.get("ATTACK_SURFACE_NO_AUTOTERM"):
        return False  # tests / headless runs: don't pop windows
    candidates = [os.environ.get("TERMINAL"), "foot", "kitty", "alacritty",
                  "x-terminal-emulator", "gnome-terminal", "konsole",
                  "xfce4-terminal", "xterm"]
    full = f"{attach_cmd}; exec bash"
    for cand in candidates:
        if not cand or not shutil.which(cand):
            continue
        try:
            if "gnome-terminal" in cand:
                subprocess.Popen([cand, "--", "bash", "-lc", full],
                                 start_new_session=True)
            else:
                subprocess.Popen([cand, "-e", "bash", "-lc", full],
                                 start_new_session=True)
            return True
        except Exception:
            continue
    return False


def open_terminal(tool: str, cmd: str, target: str, finding: str = "") -> Dict[str, Any]:
    """Open an interactive terminal with the attack command PRE-FILLED.

    The command is inserted at the prompt but NOT executed — the operator
    reviews it and presses Enter. Sessions live inside the Kali tool
    container (tmux), so every required binary is present.

    Returns: {ok, session, attach_cmd, cmd, auto_opened} or {ok: False, error}.
    """
    binary = TOOL_WHITELIST.get(tool)
    if not binary or not cmd.strip():
        return {"ok": False, "error": "unknown tool or empty command"}
    if "\n" in cmd or "\r" in cmd:
        return {"ok": False, "error": "multi-line commands are not allowed"}
    runner = _runner_for(tool)
    if runner is None:
        return {"ok": False, "error": f"tool not available: {tool}"}

    session = "as_" + re.sub(r"[^A-Za-z0-9_-]", "", tool) + "_" + uuid.uuid4().hex[:6]
    inner = cmd.strip()

    try:
        if runner == "container":
            subprocess.run(
                ["docker", "exec", "-d", KALI_CONTAINER, "tmux", "new-session",
                 "-d", "-s", session, "-x", "200", "-y", "50"],
                check=True, capture_output=True, timeout=20)
            # send-keys WITHOUT Enter → command sits at the prompt.
            # Retry: the tmux server inside the container may still be
            # booting when the first docker exec returns.
            last_err = None
            for _ in range(5):
                try:
                    subprocess.run(
                        ["docker", "exec", KALI_CONTAINER, "tmux", "send-keys",
                         "-t", session, "-l", inner],
                        check=True, capture_output=True, timeout=20)
                    last_err = None
                    break
                except subprocess.CalledProcessError as e:
                    last_err = e
                    time.sleep(0.6)
            if last_err is not None:
                raise last_err
            attach = f"docker exec -it {KALI_CONTAINER} tmux attach -t {session}"
        else:
            subprocess.run(["tmux", "kill-session", "-t", session],
                           capture_output=True, timeout=10)
            subprocess.run(
                ["tmux", "new-session", "-d", "-s", session, "-x", "200", "-y", "50"],
                check=True, capture_output=True, timeout=20)
            subprocess.run(["tmux", "send-keys", "-t", session, "-l", inner],
                           check=True, capture_output=True, timeout=20)
            attach = f"tmux attach -t {session}"
    except Exception as e:
        return {"ok": False, "error": f"terminal prep failed: {e}"}

    _audit(f"TERMINAL {session} tool={tool} target={target} cmd={inner[:150]}")
    opened = _spawn_local_terminal(attach)
    return {"ok": True, "session": session, "attach_cmd": attach,
            "cmd": inner, "target": target, "finding": finding[:120],
            "auto_opened": opened}
