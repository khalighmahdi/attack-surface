"""
modules/correlation_engine.py
===============================
Generates human-readable findings and recommendations.

Accepts both old (v0.1) and new (v0.7) shapes to stay compatible with
the legacy scanner.py and the new runner.py.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("AttackSurface")


def _as_list(value):
    """Best-effort coerce a value to a list of strings."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        # Common shape: {open_ports: [...]} or {technologies: [...]}
        for key in ("technologies", "open_ports", "issues", "missing", "info_leaks"):
            if key in value and isinstance(value[key], list):
                return value[key]
        return []
    if isinstance(value, str):
        return [value]
    return [str(value)]


def generate_findings(host, risk=None, tech=None, ports=None, misconf=None):
    """
    Build a list of human-readable findings for a single host.

    Args:
        host:    str (domain) or dict (host_info)
        risk:    dict with keys score, level, reasons
        tech:    list[str] OR dict (technologies wrapper)
        ports:   list[dict] OR dict ({open_ports: [...]})
        misconf: dict with keys 'missing' (list) and 'info_leaks' (list)
    """
    risk = risk or {}
    misconf = misconf or {}
    tech_list = _as_list(tech)
    ports_list = _as_list(ports)
    missing_headers = misconf.get("missing") or []
    info_leaks = misconf.get("info_leaks") or []

    findings = []

    # 1. High Risk Finding
    level = (risk.get("level") or "").lower()
    if level in ("high", "critical"):
        findings.append(
            f"The host presents a **{level.upper()}** risk score "
            f"({risk.get('score', 0)}). Immediate review of exposed "
            f"services and configuration is recommended."
        )

    # 2. Port Findings
    critical_ports = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP"}
    for p in ports_list:
        if not isinstance(p, dict):
            continue
        port_num = p.get("port")
        if port_num in critical_ports:
            findings.append(
                f"**Public Exposure**: {critical_ports[port_num]} "
                f"({p.get('service', 'unknown')}) is open on port {port_num} "
                f"and should be restricted to internal networks or secured with a VPN."
            )

    # 3. Misconfiguration
    if missing_headers:
        findings.append(
            f"**Missing Security Headers**: Critical security headers are "
            f"missing: {', '.join(missing_headers)}. This exposes users to "
            f"clickjacking, XSS, and content sniffing vulnerabilities."
        )

    if info_leaks:
        findings.append(
            f"**Server Information Leak**: The server reveals sensitive "
            f"version information ({len(info_leaks)} items). These headers "
            f"should be removed or obfuscated."
        )

    # Also surface header_audit issues if passed via misconf
    if not missing_headers:
        for issue in _as_list(misconf.get("issues")):
            findings.append(f"**Header Issue**: {issue}")

    # 4. Technology
    if any("WordPress" in t for t in tech_list):
        findings.append(
            "**Known Technology**: WordPress CMS detected. Ensure all themes, "
            "plugins, and core files are up to date to prevent exploitation."
        )

    logger.debug("Findings generated for %s: %d items", host, len(findings))
    return findings
