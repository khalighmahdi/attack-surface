"""Minimal MCP (Model Context Protocol) server for Attack Surface Scanner.

Runs over stdio (JSON-RPC 2.0). It exposes a small, safe, read-only (no
exploitation) toolset so any MCP-capable agent (OpenCode, Claude Desktop,
Cursor, ...) can drive scans and read results.

Usage:
    python attack_surface.py mcp
    # or, in an MCP client:
    { "command": ["python", "/path/to/attack_surface.py", "mcp"] }

Nothing is printed to stdout except JSON-RPC frames; diagnostics go to stderr.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "attack_surface.py"
PYTHON = sys.executable
REPORTS = ROOT / "reports"
JOBS: Dict[str, Dict[str, Any]] = {}


def _log(msg: str) -> None:
    sys.stderr.write(f"[mcp] {msg}\n")
    sys.stderr.flush()


def _write(frame: Dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(frame, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _result(req_id: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _text(text: str) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": False}


def _err_text(text: str) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": True}


TOOLS: List[Dict[str, Any]] = [
    {
        "name": "project_info",
        "description": "Return the Attack Surface project path and version.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "run_scan",
        "description": (
            "Start a read-only attack-surface scan for a domain the caller is "
            "authorized to test. Returns immediately with a job id; poll with "
            "scan_status. Defaults are safe-mode (no brute force/exploitation)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain, e.g. example.com"},
                "max_subdomains": {"type": "integer", "default": 50, "minimum": 1},
                "rate": {"type": "number", "default": 5.0, "minimum": 0.1},
                "cves_deep": {"type": "boolean", "default": True},
                "poc": {"type": "boolean", "default": True},
                "mitre": {"type": "boolean", "default": True},
                "redteam": {"type": "boolean", "default": True},
                "no_ports": {"type": "boolean", "default": False},
                "no_critical_web": {"type": "boolean", "default": False},
                "cloud": {"type": "boolean", "default": False},
                "api_scan": {"type": "boolean", "default": False},
            "fast": {"type": "boolean", "default": False},
            "redteam_safe": {"type": "boolean", "default": False},
            "hunt": {"type": "boolean", "default": False},
            "proof_pack": {"type": "boolean", "default": False},
            "loot": {"type": "boolean", "default": False},
            "screenshots": {"type": "boolean", "default": False},
            },
            "required": ["domain"],
            "additionalProperties": False,
        },
    },
    {
        "name": "scan_status",
        "description": "Check a previously started scan job (by job id) and return its tail output.",
        "inputSchema": {
            "type": "object",
            "properties": {"job_id": {"type": "string"}},
            "required": ["job_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_scans",
        "description": "List stored scans (id, domain, risk score/level, timestamp) from the local DB.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "start_dashboard",
        "description": "Start the web Operations Console and return its URL.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "port": {"type": "integer", "default": 8443, "minimum": 1, "maximum": 65535},
                "host": {"type": "string", "default": "127.0.0.1"},
            },
            "additionalProperties": False,
        },
    },
]


def _handle_tool(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    if name == "project_info":
        version = "unknown"
        vp = ROOT / "core" / "version.py"
        if vp.exists():
            for line in vp.read_text().splitlines():
                if line.strip().startswith("__version__"):
                    version = line.split("=", 1)[1].strip().strip('"\'')
                    break
        return _text(f"Attack Surface Scanner\npath={ROOT}\nversion={version}")

    if name == "run_scan":
        domain = (args.get("domain") or "").strip()
        if not domain:
            return _err_text("domain is required")

        job_id = uuid.uuid4().hex[:8]
        REPORTS.mkdir(parents=True, exist_ok=True)
        log_path = REPORTS / f"mcp_scan_{job_id}_{domain}.log"
        cmd = [PYTHON, str(CLI), "-d", domain]
        if args.get("no_ports"):
            cmd.append("--no-ports")
        if args.get("no_critical_web"):
            cmd.append("--no-critical-web")
        if args.get("cloud"):
            cmd.append("--cloud")
        if args.get("api_scan"):
            cmd.append("--api-scan")
        if args.get("fast"):
            cmd.append("--fast")
        if args.get("redteam_safe"):
            cmd.append("--redteam-safe")
        if args.get("hunt"):
            cmd.append("--hunt")
        if args.get("proof_pack"):
            cmd.append("--proof-pack")
        if args.get("loot"):
            cmd.append("--loot")
        if args.get("screenshots"):
            cmd.append("--screenshots")
        if args.get("cves_deep", True):
            cmd.append("--cves-deep")
        if args.get("poc", True):
            cmd.append("--poc")
        if args.get("mitre", True):
            cmd.append("--mitre")
        if args.get("redteam", True):
            cmd.append("--redteam")
        cmd += ["--rate", str(args.get("rate", 5.0)),
                "--max-subdomains", str(args.get("max_subdomains", 50))]

        try:
            fh = open(log_path, "w", buffering=1)
            proc = subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT, cwd=str(ROOT))
        except Exception as e:  # pragma: no cover
            return _err_text(f"failed to launch scan: {e}")

        JOBS[job_id] = {
            "proc": proc,
            "log": log_path,
            "fh": fh,
            "domain": domain,
            "started": time.time(),
        }
        return _text(
            f"Scan started.\njob_id={job_id}\ndomain={domain}\nlog={log_path}\n"
            f"Poll with scan_status(job_id='{job_id}')."
        )

    if name == "scan_status":
        job_id = args.get("job_id")
        job = JOBS.get(job_id)
        if not job:
            return _err_text(f"unknown job_id: {job_id}")
        proc = job["proc"]
        rc = proc.poll()
        elapsed = round(time.time() - job["started"], 1)
        tail = ""
        try:
            with open(job["log"]) as f:
                lines = f.readlines()
            tail = "".join(lines[-25:])
        except OSError:
            pass
        if rc is None:
            state = "running"
        elif rc == 0:
            state = "completed"
        else:
            state = f"failed (exit {rc})"
        # close file handle once done
        if rc is not None:
            try:
                job["fh"].close()
            except Exception:
                pass
        return _text(
            f"job_id={job_id}\ndomain={job['domain']}\nstate={state}\nelapsed={elapsed}s\n"
            f"log={job['log']}\n----- tail -----\n{tail}"
        )

    if name == "list_scans":
        try:
            import db_store  # local import keeps server importable
            rows = db_store.list_scans()
        except Exception as e:
            return _err_text(f"list_scans failed: {e}")
        if not rows:
            return _text("No stored scans yet.")
        lines = [f"{'ID':>4}  {'Timestamp':<20} {'Domain':<28} {'Score':>6}  Level"]
        for r in rows[:50]:
            lines.append(
                f"{r['id']:>4}  {r['ts']:<20} {r['domain']:<28} "
                f"{(r['risk_score'] if r['risk_score'] is not None else '-'):>6}  "
                f"{r['risk_level'] or ''}"
            )
        return _text("\n".join(lines))

    if name == "start_dashboard":
        port = int(args.get("port", 8443))
        host = args.get("host", "127.0.0.1")
        REPORTS.mkdir(parents=True, exist_ok=True)
        log_path = REPORTS / "mcp_dashboard.log"
        fh = open(log_path, "w", buffering=1)
        try:
            subprocess.Popen(
                [PYTHON, str(CLI), "serve", "--port", str(port), "--host", host],
                stdout=fh, stderr=subprocess.STDOUT, cwd=str(ROOT),
                start_new_session=True,
            )
        except Exception as e:
            return _err_text(f"failed to start dashboard: {e}")
        return _text(f"Dashboard starting.\nurl=http://{host if host != '0.0.0.0' else '127.0.0.1'}:{port}/\nlog={log_path}")

    return _err_text(f"unknown tool: {name}")


def handle(msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    method = msg.get("method")
    req_id = msg.get("id")

    if method == "initialize":
        params = msg.get("params") or {}
        return _result(req_id, {
            "protocolVersion": params.get("protocolVersion", "2025-03-26"),
            "capabilities": {"tools": {"listChanged": False}, "resources": {}},
            "serverInfo": {"name": "attack-surface", "version": "0.23.0"},
        })

    if method == "notifications/initialized":
        return None

    if method == "ping":
        return _result(req_id, {})

    if method == "tools/list":
        return _result(req_id, {"tools": TOOLS})

    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        try:
            res = _handle_tool(name, args)
        except Exception as e:  # pragma: no cover - defensive
            _log(f"tool {name} crashed: {e}")
            res = _err_text(f"internal error: {e}")
        return _result(req_id, res)

    # Unknown method. 'id' may be missing for notifications.
    if req_id is not None:
        return _error(req_id, -32601, f"method not found: {method}")
    return None


def main() -> int:
    _log("MCP server ready (stdio)")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            _write(_error(None, -32700, "parse error"))
            continue
        try:
            resp = handle(msg)
        except Exception as e:  # pragma: no cover
            _log(f"handler crashed: {e}")
            resp = _error(msg.get("id"), -32603, "internal error")
        if resp is not None:
            _write(resp)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
