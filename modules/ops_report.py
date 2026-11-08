"""Ops report — turn a scan and a Knull session into a client-ready report.

The heavyweight renderer already exists (modules/reporting); this module
only adapts what the scanner and Knull actually produced into the shape it
expects, and adds the two sections only we can write: the reachability /
coverage verdict and what the autonomous agent decided.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AttackSurface.OpsReport")

_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _severity(value: Any) -> str:
    s = str(value or "info").strip().lower()
    return s if s in _SEVERITIES else "info"


def _category_of(title: str, category: str = "") -> str:
    if category:
        # keep the stored casing; only lift the first letter
        cat = str(category).strip()
        return cat[:1].upper() + cat[1:] if cat else cat
    t = (title or "").lower()
    if "public exposure" in t:
        return "Service Exposure"
    if "missing" in t and "header" in t:
        return "Missing Security Header"
    if "cve-" in t or "cve" in t.split(":")[0]:
        return "Known Vulnerability"
    if "scan coverage" in t:
        return "Scan Coverage"
    if "wordpress" in t:
        return "Technology"
    if "spoof" in t or "spf" in t or "dmarc" in t:
        return "Email Security"
    if "risk score" in t:
        return "Risk Summary"
    return "Finding"


def _findings_of(scan: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """DB findings -> the shape the reporter renders."""
    out: Dict[str, List[Dict[str, Any]]] = {}
    for f in (scan.get("findings") or []):
        host = str(f.get("host") or scan.get("domain") or "unknown")
        title = str(f.get("title") or "").strip()
        if not title:
            continue
        detail = str(f.get("detail") or "")
        if detail.startswith('"') and detail.endswith('"'):
            detail = detail[1:-1]
        out.setdefault(host, []).append({
            "title": title.replace("**", ""),
            "severity": _severity(f.get("severity")),
            "type": _category_of(title, f.get("category") or ""),
            "evidence": detail.replace("**", "")[:600],
            "description": detail.replace("**", "")[:400],
            "remediation": "",
        })
    # CVEs: the watchlist is real vulnerability data, keep it visible
    sections = scan.get("sections") or {}
    cves = sections.get("cves") or {}
    if isinstance(cves, dict):
        for host, rows in cves.items():
            for row in (rows or []):
                if not isinstance(row, dict):
                    continue
                for c in (row.get("cves") or [])[:8]:
                    if not isinstance(c, dict):
                        continue
                    cid = str(c.get("cve") or c.get("id") or "")
                    if not cid:
                        continue
                    cvss = c.get("cvss")
                    out.setdefault(str(host), []).append({
                        "title": f"{cid} (CVSS {cvss}) — {row.get('tech', '')}",
                        "severity": _severity(
                            "critical" if (cvss or 0) >= 9 else
                            "high" if (cvss or 0) >= 7 else "medium"),
                        "type": ("Known Vulnerability (exact CPE match)"
                                 if row.get("match") == "cpe_exact"
                                 else "Known Vulnerability (keyword match)"),
                        "evidence": str(c.get("summary") or "")[:600],
                        "description": ("Confirmed against the NVD CPE API."
                                        if row.get("match") == "cpe_exact"
                                        else "Candidate from an NVD keyword "
                                             "search — verify the version "
                                             "before acting."),
                        "remediation": "",
                    })
    return out


def _knull_summary(db_path: Optional[str] = None,
                   agent: Any = None) -> Dict[str, Any]:
    """What the autonomous agent decided, and what actually held up."""
    import db_store
    sb = db_store.knull_scoreboard(db_path=db_path)
    runs = db_store.list_knull_runs(limit=5, db_path=db_path)
    totals = sb.get("totals") or {}
    decided = [t for t in (sb.get("by_technique") or []) if t.get("decided")]
    return {
        "agent_id": getattr(agent, "agent_id", None),
        "running": bool(getattr(agent, "_running", False)),
        "sessions": len(runs),
        "last_session": runs[0] if runs else None,
        "decided": totals.get("decided", 0),
        "confirmed": totals.get("success", 0),
        "refuted": totals.get("failure", 0),
        "pending": totals.get("pending", 0),
        "impact": totals.get("impact", 0),
        "by_source": sb.get("by_source") or {},
        "worn_out": sb.get("worn_out") or [],
        "techniques": decided[:8],
    }


def build_report_context(db_path: Optional[str] = None,
                         agent: Any = None,
                         scan_id: Optional[int] = None,
                         domain: Optional[str] = None) -> Dict[str, Any]:
    """Assemble the ctx_data the reporting package expects."""
    import db_store

    scan = None
    if scan_id:
        try:
            scan = db_store.get_scan(int(scan_id), db_path)
        except Exception:
            scan = None
    if scan is None:
        rows = db_store.list_scans(db_path)
        if domain:
            rows = [r for r in rows if r.get("domain") == domain]
        if rows:
            scan = db_store.get_scan(rows[0]["id"], db_path)
    if scan is None:
        return {}

    sections = scan.get("sections") or {}
    reach = sections.get("reachability") or {}
    findings = _findings_of(scan)

    return {
        "meta": {
            "target": scan.get("domain"),
            "date": scan.get("ts"),
            "scan_id": scan.get("id"),
            "tool_version": scan.get("tool_version"),
            "generated_by": "attack-surface + Knull",
        },
        "analysis": {
            "risk": {"score": scan.get("risk_score") or 0,
                     "level": scan.get("risk_level") or "Unknown"},
            "findings": findings,
        },
        "coverage": reach,
        "knull": _knull_summary(db_path=db_path, agent=agent),
    }


def generate(db_path: Optional[str] = None, agent: Any = None,
             scan_id: Optional[int] = None, domain: Optional[str] = None,
             template: str = "all", fmt: str = "html",
             output_dir: str = "reports") -> Dict[str, Any]:
    """Generate the report. Returns {'ok', 'paths' | 'error'}."""
    ctx = build_report_context(db_path=db_path, agent=agent,
                               scan_id=scan_id, domain=domain)
    if not ctx:
        return {"ok": False, "error": "no scan data to report on"}
    try:
        from modules.reporting import generate_report
        paths = generate_report(ctx, template=template, format=fmt,
                                output_dir=output_dir)
    except Exception as e:
        logger.warning("ops report failed: %s", e)
        return {"ok": False, "error": str(e)[:300]}
    written = {k: v for k, v in (paths or {}).items() if v}
    return {"ok": True, "paths": written,
            "target": ctx["meta"]["target"],
            "coverage": ctx["coverage"].get("state", "unknown"),
            "findings": sum(len(v) for v in ctx["analysis"]["findings"].values())}


def read_report(path: str, output_dir: str = "reports") -> Optional[str]:
    """Read a generated report by basename, refusing traversal."""
    name = os.path.basename(str(path or ""))
    if not name:
        return None
    full = os.path.join(output_dir, name)
    if not os.path.isfile(full):
        return None
    try:
        with open(full, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError as e:
        logger.warning("cannot read report %s: %s", full, e)
        return None
