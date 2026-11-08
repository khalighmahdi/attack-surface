"""web_terminal.py — tmux-backed terminal sessions for the dashboard.

The dashboard is stdlib-only (http.server, no websockets), so the
"real terminal" is built on tmux inside the Kali tool container:

    create  → tmux new-session in kali-as
    keys    → tmux send-keys (literal, incl. Enter/Ctrl chars)
    screen  → tmux capture-pane -e  (ANSI colors preserved)

The frontend polls the screen (250 ms) and forwards keystrokes — the
operator sees a live terminal inside the browser, with the attack
command already sitting at the prompt.
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
import time
import uuid
from typing import Any, Dict, Optional

logger = logging.getLogger("AttackSurface.WebTerminal")

KALI_CONTAINER = os.environ.get("KALI_CONTAINER", "kali-as")
_SESSION_RE = re.compile(r"^as_web_[a-f0-9]{8}$")


def _docker(args: list, timeout: int = 15, check: bool = False):
    return subprocess.run(["docker", "exec"] + args,
                          capture_output=True, text=True,
                          timeout=timeout, check=check)


def create_session(cols: int = 120, rows: int = 32) -> Dict[str, Any]:
    """New tmux session inside kali-as. Returns {ok, session, error?}."""
    cols = max(40, min(int(cols or 120), 300))
    rows = max(10, min(int(rows or 32), 120))
    session = f"as_web_{uuid.uuid4().hex[:8]}"
    try:
        _docker(["-d", KALI_CONTAINER, "tmux", "new-session", "-d",
                 "-s", session, "-x", str(cols), "-y", str(rows)],
                check=True)
    except Exception as e:
        return {"ok": False, "error": f"tmux create failed: {e}"}
    # give the shell a beat to paint the prompt
    time.sleep(0.25)
    return {"ok": True, "session": session,
            "attach_hint": f"docker exec -it {KALI_CONTAINER} tmux attach -t {session}"}


def _valid(session: str) -> bool:
    return bool(_SESSION_RE.match(session or ""))


def send_keys(session: str, data: str) -> Dict[str, Any]:
    """Send keystrokes to the session. Special keys are mapped explicitly."""
    if not _valid(session):
        return {"ok": False, "error": "invalid session"}
    if not isinstance(data, str) or not data:
        return {"ok": True}  # nothing to send
    # Map control characters tmux understands as key names
    special = {"\r": "Enter", "\n": "Enter", "\x7f": "BSpace",
               "\x08": "BSpace", "\x03": "C-c", "\x04": "C-d",
               "\x1a": "C-z", "\x1b": "Escape", "\t": "Tab"}
    try:
        if data in special:
            _docker([KALI_CONTAINER, "tmux", "send-keys", "-t", session,
                     special[data]], check=True)
        else:
            # literal text (may be multi-char paste); -l avoids key parsing
            _docker([KALI_CONTAINER, "tmux", "send-keys", "-t", session,
                     "-l", data], check=True)
    except Exception as e:
        return {"ok": False, "error": f"send-keys failed: {e}"}
    return {"ok": True}


def capture(session: str) -> Dict[str, Any]:
    """ANSI screen capture. Returns {ok, screen, cursor?}."""
    if not _valid(session):
        return {"ok": False, "error": "invalid session", "screen": ""}
    try:
        r = _docker([KALI_CONTAINER, "tmux", "capture-pane", "-p", "-e",
                     "-t", session])
        if r.returncode != 0:
            return {"ok": False, "error": (r.stderr or "capture failed").strip()[:120],
                    "screen": ""}
        return {"ok": True, "screen": r.stdout or ""}
    except Exception as e:
        return {"ok": False, "error": str(e), "screen": ""}


def resize(session: str, cols: int, rows: int) -> Dict[str, Any]:
    if not _valid(session):
        return {"ok": False, "error": "invalid session"}
    try:
        _docker([KALI_CONTAINER, "tmux", "resize-window", "-t", session,
                 "-x", str(max(40, min(int(cols), 300))),
                 "-y", str(max(10, min(int(rows), 120)))])
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def kill_session(session: str) -> Dict[str, Any]:
    if not _valid(session):
        return {"ok": False, "error": "invalid session"}
    try:
        _docker([KALI_CONTAINER, "tmux", "kill-session", "-t", session])
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def prefill(session: str, command: str) -> Dict[str, Any]:
    """Type `command` at the prompt WITHOUT executing it (no Enter)."""
    return send_keys(session, command)
