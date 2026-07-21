"""
core/checkpoint.py
==================
Save and restore scan state so a long scan can be resumed.

Why
---
On a 100-subdomain target with port scans, a full run takes minutes.
If the user hits Ctrl+C, the network drops, or the host reboots, the
work is lost. Checkpointing writes the ScanContext to disk after every
phase, so `--resume file.json` can pick up where we left off.

Format
------
Plain JSON (not pickle) for transparency and forward-compatibility. We
only persist the data fields of ScanContext, not its methods.

Usage
-----
    runner = ScannerRunner(checkpoint_path="scan.json")
    runner.run_full_scan(domain)        # writes scan.json after each phase

    # later, after a crash:
    runner = ScannerRunner(resume_from="scan.json")
    runner.run_full_scan(domain)        # skips phases that are already done
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

from core.context import ScanContext

logger = logging.getLogger("AttackSurface.Checkpoint")


# Phases we know how to skip on resume. Anything not in this set is
# considered "done" if it produced output.
PHASE_NAMES = [
    "subdomains",
    "mx_records",
    "historical_dns",
    "alive_hosts",
    "ports",
    "headers",
    "technologies",
    "admin_panels",
    "primary_admin_panels",
    "origin_ips",
    "risk_scores",
    "attack_paths",
    "mitre_attack",
    "kill_chain",
    "findings",
]


def save(ctx: ScanContext, path: str) -> None:
    """Write the scan context to `path` as JSON. Best-effort."""
    try:
        data = _ctx_to_dict(ctx)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        os.replace(tmp, path)  # atomic on POSIX
        logger.debug("Checkpoint saved: %s", path)
    except Exception as e:
        logger.warning("Failed to save checkpoint to %s: %s", path, e)


def load(path: str) -> Optional[ScanContext]:
    """Load a saved checkpoint. Returns None if missing or invalid."""
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        ctx = _dict_to_ctx(data)
        logger.info("Resumed from checkpoint: %s", path)
        return ctx
    except Exception as e:
        logger.warning("Failed to load checkpoint from %s: %s", path, e)
        return None


def is_phase_done(ctx: ScanContext, phase: str) -> bool:
    """Return True if a given phase has produced output."""
    if phase == "subdomains":
        return bool(ctx.subdomains)
    if phase == "mx_records":
        return bool(ctx.mx_records)
    if phase == "historical_dns":
        return bool(ctx.historical_dns)
    if phase == "alive_hosts":
        return bool(ctx.alive_hosts)
    if phase == "ports":
        return bool(ctx.ports)
    if phase == "headers":
        return bool(ctx.headers)
    if phase == "technologies":
        return bool(ctx.technologies)
    if phase == "admin_panels":
        return bool(ctx.admin_panels)
    if phase == "primary_admin_panels":
        return bool(ctx.primary_admin_panels)
    if phase == "origin_ips":
        return bool(ctx.origin_ips)
    if phase == "risk_scores":
        return bool(ctx.risk_scores)
    if phase == "attack_paths":
        return bool(ctx.attack_paths)
    if phase == "mitre_attack":
        return bool(ctx.mitre_attack)
    if phase == "kill_chain":
        return bool(ctx.kill_chain)
    if phase == "findings":
        return bool(ctx.findings)
    return False


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _ctx_to_dict(ctx: ScanContext) -> Dict[str, Any]:
    return {
        "_version": 1,
        "domain": ctx.domain,
        "scan_time": ctx.scan_time,
        "version": ctx.version,
        "errors": list(ctx.errors),
        "events": list(ctx.events),
        "payloads": list(ctx.payloads),
        "subdomains": list(ctx.subdomains),
        "mx_records": list(ctx.mx_records),
        "historical_dns": list(ctx.historical_dns),
        "alive_hosts": list(ctx.alive_hosts),
        "ports": dict(ctx.ports),
        "headers": dict(ctx.headers),
        "technologies": dict(ctx.technologies),
        "admin_panels": dict(ctx.admin_panels),
        "primary_admin_panels": list(ctx.primary_admin_panels),
        "origin_ips": list(ctx.origin_ips),
        "risk_scores": dict(ctx.risk_scores),
        "attack_paths": list(ctx.attack_paths),
        "mitre_attack": dict(ctx.mitre_attack),
        "kill_chain": dict(ctx.kill_chain),
        "findings": dict(ctx.findings),
    }


def _dict_to_ctx(d: Dict[str, Any]) -> ScanContext:
    ctx = ScanContext(domain=d.get("domain", "unknown"))
    ctx.scan_time = d.get("scan_time", ctx.scan_time)
    ctx.version = d.get("version", ctx.version)
    ctx.errors = list(d.get("errors", []))
    ctx.events = list(d.get("events", []))
    ctx.payloads = list(d.get("payloads", []))
    ctx.subdomains = list(d.get("subdomains", []))
    ctx.mx_records = list(d.get("mx_records", []))
    ctx.historical_dns = list(d.get("historical_dns", []))
    ctx.alive_hosts = list(d.get("alive_hosts", []))
    ctx.ports = dict(d.get("ports", {}))
    ctx.headers = dict(d.get("headers", {}))
    ctx.technologies = dict(d.get("technologies", {}))
    ctx.admin_panels = dict(d.get("admin_panels", {}))
    ctx.primary_admin_panels = list(d.get("primary_admin_panels", []))
    ctx.origin_ips = list(d.get("origin_ips", []))
    ctx.risk_scores = dict(d.get("risk_scores", {}))
    ctx.attack_paths = list(d.get("attack_paths", []))
    ctx.mitre_attack = dict(d.get("mitre_attack", []))
    ctx.kill_chain = dict(d.get("kill_chain", {}))
    ctx.findings = dict(d.get("findings", []))
    return ctx



# ---------------------------------------------------------------------------
# Legacy aliases (used by core/runner.py)
# ---------------------------------------------------------------------------

def save_checkpoint(ctx: ScanContext, path: str) -> None:
    """Alias for save() — kept for compatibility with the runner."""
    save(ctx, path)


def load_checkpoint(path: str) -> Optional[ScanContext]:
    """Alias for load() — returns the context, or None on failure."""
    return load(path)


def completed_phases(ctx: ScanContext) -> List[str]:
    """Return a list of phase names that have produced output in `ctx`."""
    return [p for p in PHASE_NAMES if is_phase_done(ctx, p)]
