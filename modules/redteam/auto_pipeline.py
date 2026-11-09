"""auto_pipeline.py — Automatic Red Team Pipeline.

After a scan completes, this module automatically:
  1. Analyzes all findings for exploitability
  2. Picks the BEST red team options (highest CVSS × ease)
  3. Builds the kill chain plan for those findings
  4. Builds lateral movement plan from internal network data
  5. Stores everything as a 'redteam_pipeline' section in the scan DB
  6. Returns the full plan so the dashboard can render it

The pipeline runs automatically after every scan — no manual input.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AttackSurface.AutoPipeline")


def _score_finding(f: Dict[str, Any]) -> float:
    """Score a finding for red team priority.

    Higher score = more interesting for exploitation.
    Factors: CVSS, service type, exploit availability, public PoC.
    """
    score = 0.0

    # CVSS base score (0-10)
    cvss = f.get("cvss", f.get("cvss_score", 0))
    try:
        score += float(cvss) * 10
    except (ValueError, TypeError):
        pass

    # Severity weight
    sev = (f.get("severity", "") or "").lower()
    sev_map = {"critical": 40, "high": 30, "medium": 15, "low": 5, "info": 1}
    score += sev_map.get(sev, 0)

    # Service type bonus (network services = more exploitable)
    service = (f.get("service", f.get("title", "")) or "").lower()
    svc_bonus = {
        "ssh": 15, "rdp": 20, "smb": 25, "ftp": 18, "telnet": 22,
        "http": 10, "https": 8, "mysql": 20, "postgres": 18,
        "redis": 22, "mongo": 20, "smtp": 12, "dns": 8,
        "vnc": 20, "winrm": 25, "rmi": 18, "jmx": 15,
    }
    for svc, bonus in svc_bonus.items():
        if svc in service:
            score += bonus
            break

    # CVE existence bonus
    if f.get("cve") or f.get("cves"):
        score += 25

    # Exploit availability
    if f.get("has_exploit") or f.get("exploit_available"):
        score += 30

    # Public PoC
    if f.get("poc") or f.get("public_poc"):
        score += 15

    return score


def _is_red_teamable(f: Dict[str, Any]) -> bool:
    """Check if a finding is actionable for red team operations."""
    sev = (f.get("severity", "") or "").lower()
    if sev in ("critical", "high"):
        return True
    score = _score_finding(f)
    return score >= 30


def analyze_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Score and sort all findings for red team priority.

    Returns findings with added 'rt_score' and 'rt_priority' fields,
    sorted by score descending.
    """
    scored = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        s = _score_finding(f)
        f["rt_score"] = round(s, 1)
        f["rt_priority"] = "critical" if s >= 60 else (
            "high" if s >= 40 else (
                "medium" if s >= 20 else "low"
            )
        )
        scored.append(f)
    scored.sort(key=lambda x: x["rt_score"], reverse=True)
    return scored


def pick_best_targets(
    findings: List[Dict[str, Any]],
    max_targets: int = 5,
) -> List[Dict[str, Any]]:
    """Pick the best N targets for red team engagement.

    Deduplicates by host:port, prefers unique hosts, picks highest score per host.
    """
    best_by_host: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        host = f.get("host", f.get("target", ""))
        port = f.get("port", "")
        key = f"{host}:{port}"
        score = f.get("rt_score", 0)
        if host not in best_by_host or score > best_by_host[host].get("rt_score", 0):
            best_by_host[host] = f
    # Sort by score, take top N
    sorted_hosts = sorted(
        best_by_host.values(),
        key=lambda x: x.get("rt_score", 0),
        reverse=True,
    )
    return sorted_hosts[:max_targets]


def build_auto_pipeline(
    scan_data: Dict[str, Any],
    max_targets: int = 5,
) -> Dict[str, Any]:
    """Build the complete automatic red team pipeline from scan data.

    Returns a dict with:
      - analyzed_findings: all findings scored and sorted
      - best_targets: top N targets for engagement
      - kill_chain: weaponization + listener + interceptor + sliver
      - lateral: pivot chain from internal network
      - next_steps: ordered list of actions for the operator
    """
    # 1. Collect all findings
    findings: List[Dict[str, Any]] = []
    for h in (scan_data.get("hosts") or []):
        for svc in (h.get("services") or []):
            findings.append({
                "host": h.get("host", ""),
                "ip": h.get("ip", ""),
                "port": svc.get("port", 80),
                "service": svc.get("service", ""),
                "banner": svc.get("banner", svc.get("tech", "")),
                "severity": "medium",
            })
        for f in (h.get("findings") or []):
            if isinstance(f, dict):
                findings.append(f)
    for f in (scan_data.get("findings") or []):
        if isinstance(f, dict):
            findings.append(f)

    # Also check sections
    sections = scan_data.get("sections") or {}
    for key in ("cve_watchlist", "tech_fingerprint", "admin_panels"):
        for item in (sections.get(key) or []):
            if isinstance(item, dict):
                findings.append(item)

    if not findings:
        return {
            "analyzed_findings": [],
            "best_targets": [],
            "kill_chain": None,
            "lateral": None,
            "next_steps": ["No findings to analyze. Run a deeper scan."],
            "summary": "No findings available for red team pipeline.",
        }

    # 2. Score and sort
    analyzed = analyze_findings(findings)

    # 3. Pick best targets
    best = pick_best_targets(analyzed, max_targets=max_targets)

    # 4. Build kill chain for best targets
    kill_chain_result = None
    try:
        from modules.redteam.kill_chain import kill_chain_from_finding
        kc_plans = []
        for f in best:
            plan = kill_chain_from_finding(f)
            if plan.get("weaponization", {}).get("exploit"):
                kc_plans.append(plan)
        kill_chain_result = {"plans": kc_plans, "count": len(kc_plans)}
    except Exception as e:
        logger.warning("Kill chain build failed: %s", e)
        kill_chain_result = {"plans": [], "count": 0, "error": str(e)}

    # 5. Build lateral movement plan
    lateral_result = None
    try:
        from modules.redteam.lateral_movement import auto_pivot_chain
        lateral_result = auto_pivot_chain(scan_data)
    except Exception as e:
        logger.warning("Lateral movement build failed: %s", e)
        lateral_result = {"chain": [], "total_hops": 0, "error": str(e)}

    # 6. Generate next steps
    next_steps = []
    if kill_chain_result and kill_chain_result.get("plans"):
        top = kill_chain_result["plans"][0]
        next_steps.append(
            f"1. Review kill chain for {top['target']} "
            f"(exploit: {top['weaponization']['exploit']})"
        )
        next_steps.append("2. Start listener: click 🖥 in Kill Chain tab")
        next_steps.append("3. Fire exploit from terminal (pre-filled commands)")
        next_steps.append("4. After session: interceptor playbook auto-suggests")
    if lateral_result and lateral_result.get("chain"):
        next_steps.append(
            f"5. Lateral movement: {lateral_result['total_hops']} hop(s) "
            f"to {lateral_result['deepest_target']}"
        )
        next_steps.append("6. Run pivot chain commands in terminal")
    if not next_steps:
        next_steps = ["No exploitable findings. Run a deeper scan or try a different target."]

    return {
        "analyzed_findings": analyzed[:20],  # top 20 for display
        "best_targets": best,
        "kill_chain": kill_chain_result,
        "lateral": lateral_result,
        "next_steps": next_steps,
        "summary": (
            f"Auto pipeline: {len(analyzed)} findings analyzed, "
            f"{len(best)} best targets selected, "
            f"{kill_chain_result.get('count', 0) if kill_chain_result else 0} "
            f"kill chain(s) built, "
            f"{lateral_result.get('total_hops', 0) if lateral_result else 0} "
            f"lateral hop(s)."
        ),
    }
