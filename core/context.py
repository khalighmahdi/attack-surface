"""
core/context.py
================
Unified scan context (state container) used by every module.

Schema: v0.7.0

This is the single source of truth passed between modules during a scan.
All modules should READ from ctx and WRITE back to it. No module should
import or instantiate another module directly; the runner orchestrates them.

Keeping a single, well-documented schema here means refactoring the
pipeline is cheap: change one place, every module stays compatible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List
from datetime import datetime, timezone


def utcnow_iso() -> str:
    """ISO-8601 UTC timestamp used everywhere in reports."""
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ScanContext:
    """
    Unified scan state.

    Convention:
        - `domain`         : the target the user asked us to scan
        - `subdomains`     : list[str]                     (Phase 1)
        - `alive_hosts`    : list[dict]                    (Phase 2)
        - `ports`          : dict[host -> {open_ports, error?}]
        - `headers`        : dict[host -> {raw, issues, status, url}]
        - `technologies`   : dict[host -> [tech_name, ...]]
        - `admin_panels`         : dict[host -> [panel_dict, ...]]
        - `primary_admin_panels` : list[dict]   (the "real" control panel per host)
        - `origin_ips`     : list[dict]                    (origin events)
        - `mx_records`     : list[dict]
        - `historical_dns` : list[dict]
        - `events`         : list[dict]                    (all normalized events)
        - `risk_scores`    : dict[host -> {score, level, reasons, attack_types}]
        - `attack_paths`   : list[dict]
        - `mitre_attack`   : dict[host -> [technique, ...]]
        - `kill_chain`     : dict[stage -> count]
        - `findings`       : dict[host -> [finding_text, ...]]
        - `payloads`       : list[dict]                    (registered payloads)
    """

    domain: str

    # Phase 1: Discovery
    subdomains: List[str] = field(default_factory=list)
    mx_records: List[Dict[str, Any]] = field(default_factory=list)
    historical_dns: List[Dict[str, Any]] = field(default_factory=list)

    # Phase 2: Probing
    alive_hosts: List[Dict[str, Any]] = field(default_factory=list)
    ports: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    headers: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    technologies: Dict[str, List[str]] = field(default_factory=dict)
    admin_panels: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    primary_admin_panels: List[Dict[str, Any]] = field(default_factory=list)

    # Phase 3: Origin / Backend
    origin_ips: List[Dict[str, Any]] = field(default_factory=list)
    setup_pages: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)

    # Phase 4: Events (raw normalized events for risk engine)
    events: List[Dict[str, Any]] = field(default_factory=list)

    # Phase 5: Analysis
    risk_scores: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    mitre_attack: Dict[str, List[str]] = field(default_factory=dict)
    kill_chain: Dict[str, int] = field(default_factory=dict)
    findings: Dict[str, List[str]] = field(default_factory=dict)

    # Phase 6: Payloads
    payloads: List[Dict[str, Any]] = field(default_factory=list)

    # Blue-team (v0.9)
    blue_team_diff: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    takeover_risks: List[Dict[str, Any]] = field(default_factory=list)
    cve_watchlist: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)

    # Meta
    scan_time: str = field(default_factory=utcnow_iso)
    version: str = "v0.9.0"
    errors: List[str] = field(default_factory=list)

    # ---- Convenience helpers ----

    def add_event(self, event):
        """Append a normalized event for the risk engine."""
        if isinstance(event, dict):
            self.events.append(event)

    def add_error(self, where, msg):
        """Record a soft error (module failure) without aborting the scan."""
        self.errors.append(f"[{where}] {msg}")

    @property
    def target(self):
        """Alias for domain (older modules used `target`)."""
        return self.domain

    def to_report_dict(self):
        """
        Convert ctx into the dict shape expected by report.py and exporter.py
        (schema v0.3.x-compatible). Used by the export step.
        """
        scores = [v.get("score", 0) for v in self.risk_scores.values() if isinstance(v, dict)]
        overall_score = round(sum(scores) / len(scores), 2) if scores else 0

        if overall_score >= 75:
            overall_level = "Critical"
        elif overall_score >= 40:
            overall_level = "High"
        elif overall_score >= 20:
            overall_level = "Medium"
        else:
            overall_level = "Low"

        risk_details = {}
        for host, info in self.risk_scores.items():
            if isinstance(info, dict):
                risk_details[host] = info.get("reasons", [])

        return {
            "meta": {
                "target": self.domain,
                "version": self.version,
                "environment": "CLI",
                "scan_time": self.scan_time,
            },
            "discovery": {
                "alive_hosts": self.alive_hosts,
                "subdomains": self.subdomains,
            },
            "network": {
                "ports": self.ports,
            },
            "analysis": {
                "risk": {
                    "score": overall_score,
                    "level": overall_level,
                    "details": risk_details,
                    "per_domain": self.risk_scores,
                },
                "technologies": {
                    host: {
                        "url": f"https://{host}",
                        "status_code": 0,
                        "technologies": techs,
                    }
                    for host, techs in self.technologies.items()
                },
                "headers": self.headers,
                "findings": self.findings,
                "attack_paths": self.attack_paths,
                "mitre_attack": self.mitre_attack,
                "kill_chain": self.kill_chain,
                "admin_panels": self.admin_panels,
                "primary_admin_panels": self.primary_admin_panels,
                "setup_pages": self.setup_pages,
                "origin_ips": self.origin_ips,
                "takeover_risks": self.takeover_risks,
                "cve_watchlist": self.cve_watchlist,
                "blue_team_diff": self.blue_team_diff,
            },
        }
