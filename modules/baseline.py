"""
modules/baseline.py
====================
Blue-Team: Attack-Surface Baseline & Diff.

A defender's #1 question: "What CHANGED on my perimeter since yesterday?"
This module snapshots a scan into a compact baseline file and, on the next
scan, produces a diff:

    NEW_HOSTS          — subdomain appeared that wasn't in baseline
    GONE_HOSTS         — host disappeared (possible takeover / outage)
    NEW_OPEN_PORTS     — a port opened on a known host (backdoor? new service?)
    CLOSED_PORTS       — service stopped (patched or crashed)
    NEW_ADMIN_PANELS   — a login surface appeared
    NEW_SETUP_PAGES    — CRITICAL: half-installed CMS appeared
    RISK_DELTA         — per-host risk score moved up/down

Baselines live in reports/baselines/<domain>.json (one file, overwritten,
so cron jobs don't pile up) — pass --baseline-keep to timestamp them.

Usage from the runner is automatic when a baseline exists; CLI:
    python3 attack_surface.py -d example.com          # uses+updates baseline
    python3 attack_surface.py -d example.com --no-baseline
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

logger = logging.getLogger("AttackSurface.Baseline")

BASELINE_DIR = os.path.join("reports", "baselines")


def _snapshot(ctx) -> Dict[str, Any]:
    """Compact, diffable representation of a scan result."""
    return {
        "_version": 1,
        "_saved_at": datetime.now(timezone.utc).isoformat(),
        "domain": ctx.domain,
        "hosts": sorted(
            (h.get("domain") if isinstance(h, dict) else h) or ""
            for h in (ctx.alive_hosts or [])
        ),
        "ports": {
            host: sorted(p.get("port") for p in (info.get("open_ports") or []))
            for host, info in (ctx.ports or {}).items() if isinstance(info, dict)
        },
        "admin_panels": {
            host: sorted(
                p.get("url", "") for p in (panels or []) if isinstance(p, dict)
            )
            for host, panels in (ctx.admin_panels or {}).items()
        },
        "setup_pages": {
            host: sorted(p.get("url", "") for p in (pages or []) if isinstance(p, dict))
            for host, pages in (getattr(ctx, "setup_pages", {}) or {}).items()
        },
        "risk": {
            host: (info or {}).get("score", 0) if isinstance(info, dict) else 0
            for host, info in (ctx.risk_scores or {}).items()
        },
    }


def baseline_path(domain: str) -> str:
    safe = domain.replace("/", "_").replace(":", "_")
    return os.path.join(BASELINE_DIR, f"{safe}.json")


def load_baseline(domain: str) -> Dict[str, Any] | None:
    path = baseline_path(domain)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("baseline unreadable: %s", e)
        return None


def save_baseline(ctx) -> str:
    os.makedirs(BASELINE_DIR, exist_ok=True)
    path = baseline_path(ctx.domain)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(_snapshot(ctx), f, ensure_ascii=False, indent=2, default=str)
        logger.info("baseline saved: %s", path)
        return path
    except Exception as e:
        logger.warning("baseline save failed: %s", e)
        return ""


def diff(current: Dict[str, Any], previous: Dict[str, Any]) -> Dict[str, List]:
    """Compute the blue-team delta between two snapshots."""
    out: Dict[str, List] = {
        "NEW_HOSTS": [], "GONE_HOSTS": [],
        "NEW_OPEN_PORTS": [], "CLOSED_PORTS": [],
        "NEW_ADMIN_PANELS": [], "NEW_SETUP_PAGES": [],
        "RISK_DELTA": [],
    }
    ch, ph = set(current.get("hosts") or []), set(previous.get("hosts") or [])
    out["NEW_HOSTS"] = sorted(ch - ph)
    out["GONE_HOSTS"] = sorted(ph - ch)

    cports, pports = current.get("ports") or {}, previous.get("ports") or {}
    common = set(cports) & set(pports)
    for host in sorted(common):
        cp, pp = set(cports[host] or []), set(pports[host] or [])
        for port in sorted(cp - pp):
            out["NEW_OPEN_PORTS"].append({"host": host, "port": port})
        for port in sorted(pp - cp):
            out["CLOSED_PORTS"].append({"host": host, "port": port})

    cpan, ppan = current.get("admin_panels") or {}, previous.get("admin_panels") or {}
    for host in sorted(set(cpan) & set(ppan)):
        new_urls = set(cpan[host] or []) - set(ppan[host] or [])
        for url in sorted(new_urls):
            out["NEW_ADMIN_PANELS"].append({"host": host, "url": url})

    cset, pset = current.get("setup_pages") or {}, previous.get("setup_pages") or {}
    for host in sorted(set(cset) | set(pset)):
        for url in sorted((set(cset.get(host) or []) - set(pset.get(host) or []))):
            out["NEW_SETUP_PAGES"].append({"host": host, "url": url})

    crank, prank = current.get("risk") or {}, previous.get("risk") or {}
    for host in sorted(set(crank) & set(prank)):
        delta = (crank[host] or 0) - (prank[host] or 0)
        if abs(delta) >= 5:
            out["RISK_DELTA"].append({"host": host, "delta": delta,
                                      "now": crank[host], "was": prank[host]})
    return out
