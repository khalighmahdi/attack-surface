"""
modules/kill_chain.py
======================
Categorizes findings into Cyber Kill Chain stages.

Accepts either a dict (legacy) or a ScanContext (v0.7).
"""

from __future__ import annotations

import logging

logger = logging.getLogger("AttackSurface")

KILL_CHAIN_STAGES = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command and Control",
    "Actions on Objectives",
]

KILL_CHAIN_MAPPING = {
    "RDP is exposed": "Delivery",
    "Public Exposure": "Delivery",
    "Missing Security Header": "Exploitation",
    "Information Leak": "Reconnaissance",
    "Server Information Leak": "Reconnaissance",
    "WordPress CMS detected": "Weaponization",
    "Header Issue": "Exploitation",
    "Admin Panel": "Delivery",
    "High Risk Exposure": "Delivery",
}


def map_finding_to_kill_chain(finding):
    """Map a single finding string to a Kill Chain stage."""
    if not isinstance(finding, str):
        return "N/A"
    for keyword, stage in KILL_CHAIN_MAPPING.items():
        if keyword.lower() in finding.lower():
            return stage
    return "N/A"


def build_kill_chain(data):
    """
    Build a {stage: count} summary.

    `data` may be:
        - a dict with key 'findings'  (legacy)
        - a ScanContext (dataclass)    (new)
    """
    if hasattr(data, "findings"):
        findings_data = data.findings or {}
    elif isinstance(data, dict):
        findings_data = data.get("findings", {}) or {}
    else:
        findings_data = {}

    summary = {stage: 0 for stage in KILL_CHAIN_STAGES}
    summary["N/A"] = 0  # catch-all for unknown

    for host, findings in findings_data.items():
        if not isinstance(findings, list):
            continue
        for finding in findings:
            stage = map_finding_to_kill_chain(finding)
            summary[stage] = summary.get(stage, 0) + 1

    logger.info("Kill Chain summary built")
    return summary
