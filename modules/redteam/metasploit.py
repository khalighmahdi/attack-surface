"""Metasploit RPC Client — Real implementation for exploit matching and session management."""

from __future__ import annotations
import json
import os
import requests
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import msgpack
    HAS_MSGPACK = True
except ImportError:
    HAS_MSGPACK = False


@dataclass
class MSFModule:
    """Metasploit module info."""
    name: str
    type: str  # exploit, auxiliary, post, payload, encoder, nop
    fullname: str
    rank: int
    description: str
    references: list[str] = field(default_factory=list)
    targets: list[dict] = field(default_factory=list)
    options: dict = field(default_factory=dict)


@dataclass
class MSFSession:
    """Active Metasploit session."""
    id: int
    type: str
    tunnel_local: str
    tunnel_peer: str
    via_exploit: str
    via_payload: str
    desc: str
    info: str
    workspace: str
    session_host: str
    session_port: int
    username: str
    uuid: str
    last_checkin: str


class MSFRPCClient:
    """
    Metasploit RPC client using msgpack over HTTP.
    
    Requires: msgrpc loaded in msfconsole (or msfrpcd)
    Setup:
      1. msfconsole -q -x 'load msgrpc ServerHost=127.0.0.1 ServerPort=55553 User=msf Pass=msfpass SSL=false'
      2. Set RT_METASPLOIT_* env vars or config.yaml
    """

    def __init__(self, config=None):
        from modules.redteam.config import get_config
        if config is not None and hasattr(config, 'metasploit'):
            # Full RedTeamConfig passed, extract metasploit section
            self.config = config.metasploit
        elif config is not None and hasattr(config, 'host'):
            # MetasploitConfig passed directly
            self.config = config
        else:
            # Default
            self.config = get_config().metasploit
        self._token: Optional[bytes] = None
        self._base_url = f"http{'s' if self.config.ssl else ''}://{self.config.host}:{self.config.port}/api"
        self._session = requests.Session()
        self._session.headers.update({'Content-Type': 'binary/message-pack'})
        self._session.verify = False  # Self-signed certs

    def connect(self) -> dict[str, Any]:
        """Connect and authenticate to msgrpc."""
        try:
            # Authenticate using auth.login (noauth handled server-side)
            result = self._call("auth.login", self.config.user, self.config.password)
            if result.get("success"):
                res = result.get("result") or {}
                # msgpack may decode keys as str or bytes depending on version
                token = res.get("token") or res.get(b"token")
                self._token = token
                return {"success": True, "token": self._token}
            return result
        except Exception as e:
            return {"success": False, "error": f"Connection failed: {e}"}

    def disconnect(self):
        """Close connection."""
        if self._token:
            try:
                self._call("auth.logout", self._token)
            except Exception:
                pass
        self._token = None
        self._session.close()

    def _call(self, method: str, *args) -> dict[str, Any]:
        """Send RPC call and receive response via HTTP."""
        if not HAS_MSGPACK:
            return {"success": False, "error": "msgpack not installed. Run: uv pip install msgpack"}

        # Build request: [method, token?, params...] for authenticated calls
        # For auth.login, no token is needed
        if method == "auth.login":
            request = [method, *args]
        else:
            if not self._token:
                return {"success": False, "error": "Not authenticated. Call connect() first."}
            request = [method, self._token, *args]

        try:
            data = msgpack.packb(request, use_bin_type=True)
            resp = self._session.post(self._base_url, data=data, timeout=30)
            
            if resp.status_code != 200:
                return {"success": False, "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
            
            response = msgpack.unpackb(resp.content, raw=False)
            
            # Response format: {result: ..., token: ...} or {error: True, ...}
            if isinstance(response, dict) and response.get("error"):
                return {"success": False, "error": response.get("error_message", "Unknown error"), "error_class": response.get("error_class")}
            
            return {"success": True, "result": response}
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": f"Request failed: {e}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ==================== MODULE OPERATIONS ====================

    def module_exploit_matching_cve(self, cve: str) -> list[MSFModule]:
        """Find exploit modules matching a CVE."""
        modules = self.module_search(f"cve:{cve}")
        return [m for m in modules if m.type == "exploit"]

    def module_search(self, query: str) -> list[MSFModule]:
        """Search modules by keyword."""
        result = self._call("module.search", query)
        if not result.get("success"):
            return []

        modules = []
        rank_map = {"low": 0, "average": 100, "manual": 200, "normal": 300,
                    "good": 400, "great": 500, "excellent": 600}
        for m in result.get("result", []):
            if isinstance(m, dict):
                # msgpack may decode keys as bytes — normalize
                m = {(k.decode() if isinstance(k, bytes) else k): v
                     for k, v in m.items()}
            rank = m.get("rank", 0)
            if isinstance(rank, bytes):
                rank = rank.decode(errors="ignore")
            if isinstance(rank, str):
                rank = rank_map.get(rank.lower(), 0)
            modules.append(MSFModule(
                name=m.get("name", ""),
                type=m.get("type", ""),
                fullname=m.get("fullname", ""),
                rank=rank,
                description=m.get("description", ""),
                references=m.get("references", []),
                targets=m.get("targets", []),
                options=m.get("options", {})
            ))
        return modules

    def module_info(self, mtype: str, name: str) -> dict[str, Any]:
        """Get detailed module info including options."""
        result = self._call("module.info", mtype, name)
        if result.get("success"):
            return result.get("result", {})
        return {}

    def module_execute(self, mtype: str, name: str, options: dict[str, Any]) -> dict[str, Any]:
        """Execute a module with options."""
        result = self._call("module.execute", mtype, name, options)
        return result

    # ==================== SESSION MANAGEMENT ====================

    def session_list(self) -> list[MSFSession]:
        """List all active sessions."""
        result = self._call("session.list")
        if not result.get("success"):
            return []

        sessions = []
        for sid, sinfo in result.get("result", {}).items():
            sessions.append(MSFSession(
                id=int(sid),
                type=sinfo.get("type", ""),
                tunnel_local=sinfo.get("tunnel_local", ""),
                tunnel_peer=sinfo.get("tunnel_peer", ""),
                via_exploit=sinfo.get("via_exploit", ""),
                via_payload=sinfo.get("via_payload", ""),
                desc=sinfo.get("desc", ""),
                info=sinfo.get("info", ""),
                workspace=sinfo.get("workspace", ""),
                session_host=sinfo.get("session_host", ""),
                session_port=sinfo.get("session_port", 0),
                username=sinfo.get("username", ""),
                uuid=sinfo.get("uuid", ""),
                last_checkin=sinfo.get("last_checkin", "")
            ))
        return sessions

    def session_interact(self, session_id: int, command: str) -> dict[str, Any]:
        """Interact with a session (shell/meterpreter command)."""
        result = self._call("session.meterpreter_write", session_id, command)
        if result.get("success"):
            # Read response
            read_result = self._call("session.meterpreter_read", session_id)
            return read_result
        return result

    def session_shell_write(self, session_id: int, command: str) -> dict[str, Any]:
        """Write to a shell session."""
        return self._call("session.shell_write", session_id, command)

    def session_shell_read(self, session_id: int) -> dict[str, Any]:
        """Read from a shell session."""
        return self._call("session.shell_read", session_id)

    def session_close(self, session_id: int) -> dict[str, Any]:
        """Close a session."""
        return self._call("session.stop", session_id)

    # ==================== JOB MANAGEMENT ====================

    def job_list(self) -> dict[str, Any]:
        """List all running jobs."""
        result = self._call("job.list")
        return result.get("result", {}) if result.get("success") else {}

    def job_stop(self, job_id: int) -> dict[str, Any]:
        """Stop a job."""
        return self._call("job.stop", job_id)

    # ==================== CONSOLE OPERATIONS ====================

    def console_create(self) -> dict[str, Any]:
        """Create a new console."""
        return self._call("console.create")

    def console_destroy(self, console_id: int) -> dict[str, Any]:
        """Destroy a console."""
        return self._call("console.destroy", console_id)

    def console_write(self, console_id: int, command: str) -> dict[str, Any]:
        """Write to console."""
        return self._call("console.write", console_id, command)

    def console_read(self, console_id: int) -> dict[str, Any]:
        """Read from console."""
        return self._call("console.read", console_id)

    def console_tabs(self, console_id: int, line: str) -> dict[str, Any]:
        """Get tab completion for console."""
        return self._call("console.tabs", console_id, line)

    # ==================== DB OPERATIONS ====================

    def db_hosts(self, workspace: str = "") -> dict[str, Any]:
        """List hosts in database."""
        return self._call("db.hosts", workspace)

    def db_services(self, host: str = "", workspace: str = "") -> dict[str, Any]:
        """List services in database."""
        return self._call("db.services", host, workspace)

    def db_vulns(self, host: str = "", workspace: str = "") -> dict[str, Any]:
        """List vulnerabilities in database."""
        return self._call("db.vulns", host, workspace)

    # ==================== CORE OPERATIONS ====================

    def core_version(self) -> dict[str, Any]:
        """Get framework version."""
        result = self._call("core.version")
        return result.get("result", {}) if result.get("success") else {}

    def core_reload_modules(self) -> dict[str, Any]:
        """Reload all modules."""
        return self._call("core.reload_modules")

    def core_stop(self) -> dict[str, Any]:
        """Stop the RPC service."""
        return self._call("core.stop")


# Convenience function
def exploit_matching_cve(cve: str, config=None) -> list[MSFModule]:
    """Quick function to find exploits matching a CVE."""
    client = MSFRPCClient(config)
    if not client.connect().get("success"):
        return []
    try:
        return client.module_exploit_matching_cve(cve)
    finally:
        client.disconnect()