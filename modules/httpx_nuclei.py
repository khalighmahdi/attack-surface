"""httpx_nuclei.py — httpx HTTP probing + nuclei template scanning.

httpx: converts discovered subdomains into a live HTTP(S) inventory
       (status, title, tech, CDN, response time) — the fastest HTTP
       prober in the Kali toolkit.

nuclei: runs template-based vulnerability checks against live targets.
        Thousands of community templates cover CVEs, misconfigs, exposed
        panels, default creds, and more — real findings, not guesses.

Pipeline: subdomains → httpx (live HTTP inventory) → nuclei (vuln scan)
          → findings flow into msf_map, cred_engine, and terminal flow.

Evasion: uses waf_evasion module to detect and bypass BitNinja,
         Cloudflare, Sucuri, Imperva, ModSecurity, and other WAF/anti-bot
         solutions. Adaptive rate limiting + realistic browser headers +
         cookie echo + headless fallback for JS challenges.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

from .waf_evasion import (
    build_httpx_command,
    build_nuclei_command,
    detect_waf,
    get_evasion_strategy,
    normalize_nuclei_finding,
    scan_with_evasion,
    CookieJar,
    AdaptiveRateLimiter,
)

logger = logging.getLogger("AttackSurface.HttpxNuclei")

KALI_CONTAINER = os.environ.get("KALI_CONTAINER", "kali-as")


def _run_in_kali(cmd: List[str], timeout: int = 300,
                 stdin_data: str = "") -> subprocess.CompletedProcess:
    """Run a command inside the Kali tool container."""
    full = ["docker", "exec", "-i", KALI_CONTAINER] + cmd
    return subprocess.run(full, capture_output=True, text=True,
                          timeout=timeout, input=stdin_data)


def _run_local(cmd: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
    """Run a command on the local host."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _runner(cmd: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
    """Prefer local binary; fall back to Kali container."""
    if os.path.exists(f"/usr/bin/{cmd[0]}") or os.path.exists(f"/usr/local/bin/{cmd[0]}"):
        return _run_local(cmd, timeout)
    return _run_in_kali(cmd, timeout)


# ---------------------------------------------------------------------------
# httpx — HTTP probing
# ---------------------------------------------------------------------------

def _write_targets_in_kali(targets: List[str]) -> str:
    """Write targets to a file INSIDE the kali-as container; return the path."""
    container_path = "/tmp/as_targets.txt"
    payload = "\n".join(t.strip() for t in targets if t.strip()) + "\n"
    subprocess.run(
        ["docker", "exec", "-i", KALI_CONTAINER, "bash", "-c",
         f"cat > {container_path}"],
        input=payload, capture_output=True, text=True, timeout=30)
    return container_path


def probe_http(subdomains: List[str], timeout: int = 300,
               rate_limit: int = 15, use_evasion: bool = True) -> List[Dict[str, Any]]:
    """Probe subdomains with httpx; return live HTTP(S) inventory.

    With use_evasion=True, detects WAFs and applies adaptive strategy:
    - Realistic browser headers (UA + Sec-Fetch + sec-ch-ua)
    - Rate limiting (slower for WAF-protected targets)
    - Cookie echo for BitNinja/Cloudflare/Sucuri
    - Headless fallback for JS challenges

    Each result: {url, status, title, tech, cdn, content_length, words, lines, waf_detected}
    """
    if not subdomains:
        return []

    if use_evasion:
        return _probe_http_evasion(subdomains, timeout, rate_limit)

    # Legacy path (no evasion) — kept for backward compatibility
    container_path = _write_targets_in_kali(subdomains)
    try:
        cmd = ["httpx", "-l", container_path, "-silent", "-status-code",
               "-title", "-tech-detect", "-content-length", "-web-server",
               "-ip", "-cname", "-cdn", "-rt", "-threads", str(rate_limit),
               "-timeout", "8", "-json"]
        r = _run_in_kali(cmd, timeout)
        results = []
        for line in (r.stdout or "").strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            techs = d.get("tech") or []
            if isinstance(techs, str):
                techs = [techs]
            results.append({
                "url": d.get("url") or d.get("input", ""),
                "status": d.get("status_code") or d.get("status", 0),
                "title": (d.get("title") or "")[:120],
                "tech": techs[:10],
                "cdn": bool(d.get("cdn", False)),
                "web_server": d.get("webserver") or d.get("server", ""),
                "ip": d.get("host") or d.get("ip", ""),
                "content_length": d.get("content_length", 0),
                "words": d.get("words", 0),
                "lines": d.get("lines", 0),
                "response_time": d.get("response_time", ""),
                "waf_detected": [],
            })
        logger.info("httpx: %d live HTTP targets from %d subdomains",
                    len(results), len(subdomains))
        return results
    except Exception as e:
        logger.warning("httpx probe failed: %s", e)
        return []
    finally:
        subprocess.run(["docker", "exec", KALI_CONTAINER, "rm", "-f", container_path],
                       capture_output=True, timeout=15)


def _probe_http_evasion(subdomains: List[str], timeout: int = 300,
                        rate_limit: int = 15) -> List[Dict[str, Any]]:
    """Evasion-aware httpx probe using waf_evasion module."""
    try:
        result = scan_with_evasion(
            targets=subdomains,
            scan_type="httpx",
            rate_limit=rate_limit,
            timeout=min(timeout, 300),
        )
        waf_detected = result.get("waf_detected", [])
        strategy = result.get("strategy", {})
        if waf_detected:
            waf_names = [w["waf"] for w in waf_detected[:3]]
            logger.info("httpx evasion: detected WAFs=%s, strategy=%s",
                        waf_names, strategy.get("description", "default"))
        return result.get("results", [])
    except Exception as e:
        logger.warning("httpx evasion probe failed: %s", e)
        return []


# ---------------------------------------------------------------------------
# nuclei — template-based vulnerability scanning
# ---------------------------------------------------------------------------

def run_nuclei(targets: List[str], severity: str = "low,medium,high,critical",
               timeout: int = 300, templates: str = "",
               rate_limit: int = 10, use_evasion: bool = True) -> List[Dict[str, Any]]:
    """Run nuclei against live targets; return findings.

    With use_evasion=True, detects WAFs and applies adaptive strategy:
    - Reduced rate limit (capped at 10 for WAF protection)
    - More retries (2 instead of 1)
    - Headless mode for JS-challenged targets
    - Realistic browser headers

    Each finding: {url, template_id, severity, name, matched_at, type, cve, waf_detected}
    """
    if not targets:
        return []

    if use_evasion:
        return _run_nuclei_evasion(targets, severity, timeout, templates, rate_limit)

    # Legacy path (no evasion)
    container_path = _write_targets_in_kali(targets)
    try:
        cmd = ["nuclei", "-l", container_path, "-severity", severity,
               "-silent", "-j", "-timeout", "10",
               "-rate-limit", str(rate_limit), "-retries", "1"]
        if templates:
            cmd += ["-t", templates]
        r = _run_in_kali(cmd, timeout)
        results = []
        for line in (r.stdout or "").strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            finding = normalize_nuclei_finding(d)
            finding["waf_detected"] = []
            results.append(finding)
        logger.info("nuclei: %d findings from %d targets", len(results), len(targets))
        return results
    except Exception as e:
        logger.warning("nuclei scan failed: %s", e)
        return []
    finally:
        subprocess.run(["docker", "exec", KALI_CONTAINER, "rm", "-f", container_path],
                       capture_output=True, timeout=15)


def _run_nuclei_evasion(targets: List[str], severity: str, timeout: int,
                        templates: str, rate_limit: int) -> List[Dict[str, Any]]:
    """Evasion-aware nuclei scan using waf_evasion module."""
    try:
        result = scan_with_evasion(
            targets=targets,
            scan_type="nuclei",
            severity=severity,
            rate_limit=rate_limit,
            timeout=timeout,
            templates=templates,
        )
        waf_detected = result.get("waf_detected", [])
        strategy = result.get("strategy", {})
        if waf_detected:
            waf_names = [w["waf"] for w in waf_detected[:3]]
            logger.info("nuclei evasion: detected WAFs=%s, strategy=%s",
                        waf_names, strategy.get("description", "default"))
        return result.get("results", [])
    except Exception as e:
        logger.warning("nuclei evasion scan failed: %s", e)
        return []


def self_extract_cve(info: Dict[str, Any]) -> str:
    """Extract CVE ID from nuclei template info."""
    cve = info.get("cve") or info.get("cve-id") or ""
    if isinstance(cve, list):
        cve = cve[0] if cve else ""
    if not cve:
        # check classification
        cls = info.get("classification") or {}
        cve = cls.get("cve-id") or cls.get("cve", "")
    return str(cve)[:30]


# ---------------------------------------------------------------------------
# Full pipeline
# ---------------------------------------------------------------------------

def full_http_scan(subdomains: List[str], domain: str = "",
                   run_nuclei_scan: bool = True,
                   severity: str = "medium,high,critical",
                   timeout: int = 600) -> Dict[str, Any]:
    """Full pipeline: subdomains → httpx → nuclei.

    Returns {http_results, nuclei_findings, stats}.
    """
    http_results = probe_http(subdomains, timeout=min(timeout, 300))
    live_urls = [r["url"] for r in http_results if r.get("url")]

    nuclei_findings = []
    if run_nuclei_scan and live_urls:
        nuclei_findings = run_nuclei(live_urls, severity=severity,
                                     timeout=timeout)

    # build findings text for the scan context
    findings = []
    for f in nuclei_findings:
        sev = f.get("severity", "info")
        tag = f.get("template_id", "")
        cve = f.get("cve", "")
        name = f.get("name", "")
        url = f.get("url", "")
        cve_tag = f" [{cve}]" if cve else ""
        findings.append(f"[{sev.upper()}] {name}{cve_tag} on {url}")

    stats = {
        "subdomains_probed": len(subdomains),
        "http_live": len(http_results),
        "nuclei_findings": len(nuclei_findings),
        "by_severity": {},
    }
    for f in nuclei_findings:
        s = f.get("severity", "info")
        stats["by_severity"][s] = stats["by_severity"].get(s, 0) + 1

    return {
        "http_results": http_results,
        "nuclei_findings": nuclei_findings,
        "findings_text": findings,
        "stats": stats,
    }
