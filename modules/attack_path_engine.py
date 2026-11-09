"""
modules/attack_path_engine.py
==============================
Infers possible attack paths from discovered data.

Accepts the unified ScanContext (v0.7) — either a dict (legacy)
or a dataclass — to read:
    - alive_hosts
    - ports
    - admin_panels
    - risk_scores
"""

from __future__ import annotations

import logging

logger = logging.getLogger("AttackSurface")


def _norm(d):
    if not d:
        return ""
    if isinstance(d, dict):
        d = d.get("domain", "")
    return str(d).replace("https://", "").replace("http://", "").split("/")[0].lower()


def _get(d, *keys, default=None):
    """Dict.get with chain support (dataclass OR dict)."""
    for k in keys:
        if d is None:
            return default
        if isinstance(d, dict):
            d = d.get(k)
        else:
            d = getattr(d, k, None)
    return d if d is not None else default


def build_attack_paths(data):
    paths = []

    domains = [
        _norm(h) for h in _get(data, "alive_hosts", default=[]) or []
    ]
    ports_map = _get(data, "ports", default={}) or {}
    admins_map = _get(data, "admin_panels", default={}) or {}
    risks_map = _get(data, "risk_scores", default={}) or {}

    # risk_scores can be either {host: {score, ...}} or {host: {per_domain: ...}}
    # in the new schema, risk_scores IS the per_domain dict.

    for d in domains:
        if not d:
            continue

        # 1. High-risk exposure
        risk_info = risks_map.get(d, {}) if isinstance(risks_map, dict) else {}
        if isinstance(risk_info, dict):
            score = risk_info.get("score", 0)
        else:
            score = 0
        if score and score >= 40:
            paths.append({
                "source_host": d,
                "path_type": "High Risk Exposure",
                "risk_score": score,
            })

        # 2. Service-based initial access (RDP)
        host_ports = ports_map.get(d, {}) if isinstance(ports_map, dict) else {}
        open_ports = host_ports.get("open_ports", []) if isinstance(host_ports, dict) else []
        for p in open_ports:
            if isinstance(p, dict) and p.get("port") == 3389:
                paths.append({
                    "source_host": d,
                    "target_service": "RDP",
                    "path_type": "Initial Access",
                })

        # 3. Admin panel correlation
        host_admins = admins_map.get(d, []) if isinstance(admins_map, dict) else []
        for a in host_admins:
            if isinstance(a, dict) and a.get("panel_type") == "admin":
                paths.append({
                    "source_host": d,
                    "target_service": "Admin Panel",
                    "path_type": (
                        "Critical Initial Access"
                        if not a.get("protected")
                        else "Authenticated Attack Surface"
                    ),
                })

    logger.info("Identified %d attack paths", len(paths))
    return paths
