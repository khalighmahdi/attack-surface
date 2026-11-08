"""html_report.py — Nessus-grade HTML report (English, print-ready).

Sections:
  1. Executive summary (risk donut + KPI grid)
  2. Vulnerability table (severity-sorted, CVSS/EPSS/KEV/exploit columns)
  3. Finding detail cards (Evidence → Impact → Remediation)
  4. CVE intelligence table (contextual risk, KEV dates, exploit links)
  5. Host inventory + subdomains

Pure stdlib; opens in any browser; print → PDF friendly.
"""
from __future__ import annotations

import html
import json
import os
from datetime import datetime
from typing import Any, Dict, List

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_RE_MAP = [
    ("critical", ("critical", "rce", "sql inj", "database port", "takeover")),
    ("high", ("high", "admin panel", "spoof", "exposed", "default cred")),
    ("medium", ("medium", "moderate", "missing", "header")),
    ("low", ("low", "info", "note")),
]


def _esc(s: Any) -> str:
    return html.escape(str(s if s is not None else ""), quote=True)


def _sev_of(text: str, hint: str | None = None) -> str:
    if hint and hint.lower() in _SEV_ORDER:
        return hint.lower()
    t = text.lower()
    for sev, keys in _SEV_RE_MAP:
        if any(k in t for k in keys):
            return sev
    return "info"


def _wrap(text: str, width: int = 100) -> List[str]:
    out: List[str] = []
    for para in str(text or "").splitlines() or [""]:
        line = ""
        for w in para.split():
            if len(line) + len(w) + 1 > width:
                out.append(line)
                line = w
            else:
                line = (line + " " + w).strip()
        out.append(line)
    return out or [""]


_RECOMMEND = {
    "email-spoof": "Publish strict SPF (~all), enable DKIM signing, add DMARC p=reject with rua reporting.",
    "database port": "Restrict the database port with a firewall to trusted IPs only; never expose 3306/5432/6379/21 to the internet.",
    "admin panel": "Move the admin panel behind VPN/allow-list, enforce strong auth + rate limiting, and disable directory listing.",
    "header": "Add Strict-Transport-Security, Content-Security-Policy, X-Frame-Options DENY and Referrer-Policy headers.",
    "takeover": "Remove the dangling DNS record or reclaim the third-party service immediately — full subdomain takeover is trivial for attackers.",
    "tls": "Renew/replace the certificate, disable TLS < 1.2, enable HSTS preload.",
}


def _remediation(title: str) -> str:
    t = title.lower()
    for key, rec in _RECOMMEND.items():
        if key in t:
            return rec
    return "Review the exposed service, apply vendor patches, and restrict access to the minimum required surface."


def build_html_report(results: Dict[str, Any], domain: str, out_path: str,
                      cve_intel: List[Dict[str, Any]] | None = None,
                      host_ips: Dict[str, str] | None = None) -> str:
    """results: {risk, findings{host:[...]}, hosts[], subdomains[]} (db-normalized)."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    risk = results.get("risk") or {}
    score = risk.get("overall_score", 0)
    level = (risk.get("overall_level") or "Low").upper()
    findings: Dict[str, List[Any]] = results.get("findings") or {}
    hosts = results.get("hosts") or []
    subs = results.get("subdomains") or []

    # ---- normalize findings -> [(host, sev, title, raw)]
    rows: List[tuple] = []
    if isinstance(findings, list):
        # DB rows: [{host, title, severity, detail...}]
        grouped: Dict[str, List[Any]] = {}
        for row in findings:
            grouped.setdefault(row.get("host", "?"), []).append(row)
        findings = grouped
    for host, flist in findings.items():
        for f in flist or []:
            if isinstance(f, dict) and "title" in f and "host" not in f:
                title = f.get("title") or "Finding"
                sev = _sev_of(title, f.get("severity"))
            elif isinstance(f, dict):
                title = f.get("title") or "Finding"
                sev = _sev_of(title, f.get("severity"))
            else:
                title = str(f)
                sev = _sev_of(title)
            rows.append((host, sev, title, f))
    rows.sort(key=lambda r: _SEV_ORDER.get(r[1], 9))
    counts = {s: sum(1 for r in rows if r[1] == s) for s in _SEV_ORDER}
    total = len(rows)
    live_hosts = [h for h in hosts if (h.get("host") if isinstance(h, dict) else h)]

    # ---- donut conic percentages
    cum = 0.0
    segs = []
    donut_colors = {"critical": "#f85149", "high": "#db6d28",
                    "medium": "#d29922", "low": "#3fb950", "info": "#8b98a5"}
    for s in ("critical", "high", "medium", "low", "info"):
        if counts[s]:
            frac = counts[s] / max(total, 1) * 100
            segs.append(f"{donut_colors[s]} {cum:.1f}% {cum+frac:.1f}%")
            cum += frac
    donut_css = ", ".join(segs) or "#242e3a 0 100%"

    # ---- finding cards
    cards = []
    for i, (host, sev, title, raw) in enumerate(rows[:60], 1):
        detail = ""
        if isinstance(raw, dict):
            detail = raw.get("detail") or raw.get("description") or ""
        rec = _remediation(title)
        cards.append(f"""
<div class="finding sev-{sev}">
 <div class="f-head"><span class="f-id">F-{i:03d}</span>
  <span class="sev-badge sv-{sev}">{sev.upper()}</span>
  <span class="f-title">{_esc(title[:110])}</span></div>
 <table class="f-meta"><tr>
   <td class="k">Host</td><td class="mono">{_esc(host)}</td></tr></table>
 <div class="f-sec"><b>Impact</b><p>{_esc(_wrap(title, 120)[0])}. {" ".join(_wrap(detail, 120)) if detail else "Assessed from scan evidence on this host."}</p></div>
 <div class="f-sec"><b>Remediation</b><p>{_esc(rec)}</p></div>
</div>""")

    # ---- CVE intel table
    cve_rows = ""
    for c in (cve_intel or [])[:40]:
        epss = f"{c['epss']*100:.0f}%" if c.get("epss") is not None else "—"
        edb = c.get("exploitdb")
        msf = c.get("metasploit") or []
        mitre = c.get("mitre") or []
        edb_link = f'<a href="{_esc(edb["url"])}">EDB-{edb["edb_id"]}</a>' if edb else '<span class="muted">—</span>'
        msf_links = " · ".join(f'<a href="{_esc(m["url"])}">{_esc(m["path"])}</a>' for m in msf[:3]) if msf else '<span class="muted">—</span>'
        mitre_links = " · ".join(f'<span class="mitre-tag">{_esc(m["technique_id"])}: {_esc(m["name"])}</span>' for m in mitre[:3]) if mitre else '<span class="muted">—</span>'
        cve_rows += f"""<tr>
<td class="mono">{_esc(c['cve'])}</td>
<td>{c.get('cvss') or '—'}</td><td>{epss}</td>
<td>{'<span class="kev-yes">YES</span>' if c.get('kev') else '<span class="muted">no</span>'}</td>
<td class="risk-cell">{c.get('contextual_risk', '—')}</td>
<td>{edb_link}</td>
<td>{msf_links}</td>
<td>{mitre_links}</td>
</tr>"""

    # ---- hosts table
    host_rows = ""
    for h in hosts:
        hh = h.get("host") if isinstance(h, dict) else h
        ip = (h.get("ip") if isinstance(h, dict) else None) or (host_ips or {}).get(hh) or "—"
        proto = (h.get("protocol") if isinstance(h, dict) else None) or "—"
        host_rows += (f"<tr><td class='mono'>{_esc(hh)}</td>"
                      f"<td class='mono'>{_esc(ip)}</td><td class='mono'>{_esc(proto)}</td></tr>")

    subs_html = "".join(f"<li>{_esc(s)}</li>" for s in subs[:150])

    _HTML = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Attack Surface Report — {_esc(domain)}</title>
<style>
:root{{--bg:#0e1116;--panel:#151a21;--bd:#242e3a;--tx:#e6edf3;--mut:#8b98a5;--ac:#4f8ff7}}
*{{box-sizing:border-box;margin:0}}
body{{background:var(--bg);color:var(--tx);font-family:ui-sans-serif,system-ui,'Segoe UI',Arial,sans-serif;font-size:14px;padding:26px;max-width:1100px;margin:0 auto}}
h1{{font-size:22px}} h2{{font-size:15px;text-transform:uppercase;letter-spacing:1px;color:var(--mut);margin:26px 0 12px;border-bottom:1px solid var(--bd);padding-bottom:8px}}
.mono{{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}}
.muted{{color:var(--mut)}}
.meta{{color:var(--mut);font-size:12.5px;margin:6px 0 20px}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:18px 0}}
.kpi{{background:var(--panel);border:1px solid var(--bd);border-radius:10px;padding:14px}}
.kpi .n{{font-size:26px;font-weight:700}} .kpi .l{{font-size:11px;text-transform:uppercase;color:var(--mut);letter-spacing:.5px;margin-bottom:4px}}
.sum-grid{{display:grid;grid-template-columns:auto 1fr;gap:22px;align-items:center}}
.donut{{width:170px;height:170px;border-radius:50%;background:conic-gradient({donut_css});position:relative}}
.donut:after{{content:'';position:absolute;inset:44px;background:var(--bg);border-radius:50%}}
.donut b{{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;z-index:1;font-size:30px}}
.legend{{font-size:13px;line-height:2}}
.legend i{{display:inline-block;width:11px;height:11px;border-radius:3px;margin-inline-end:8px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{font-size:10.5px;text-transform:uppercase;letter-spacing:.6px;color:var(--mut);text-align:left;padding:8px 12px;border-bottom:1px solid var(--bd)}}
td{{padding:8px 12px;border-bottom:1px solid var(--bd)}}
.sev-badge{{display:inline-block;padding:2px 10px;border-radius:99px;font-size:10px;font-weight:700}}
.sv-critical{{background:rgba(248,81,73,.15);color:#f85149}}.sv-high{{background:rgba(219,109,40,.15);color:#db6d28}}
.sv-medium{{background:rgba(210,153,34,.15);color:#d29922}}.sv-low{{background:rgba(63,185,80,.15);color:#3fb950}}
.sv-info{{background:rgba(139,152,165,.15);color:#8b98a5}}
.finding{{background:var(--panel);border:1px solid var(--bd);border-inline-start:4px solid var(--mut);border-radius:10px;padding:14px 16px;margin-bottom:12px}}
.finding.sev-critical{{border-inline-start-color:#f85149}}.finding.sev-high{{border-inline-start-color:#db6d28}}
.finding.sev-medium{{border-inline-start-color:#d29922}}.finding.sev-low{{border-inline-start-color:#3fb950}}
.f-head{{display:flex;gap:10px;align-items:center;margin-bottom:8px}}
.f-id{{font-family:ui-monospace,monospace;color:var(--mut);font-size:12px}}
.f-title{{font-weight:600}}
.f-sec{{margin-top:8px;font-size:13.5px;line-height:1.55}}
.f-sec b{{color:var(--ac);font-size:11px;text-transform:uppercase;letter-spacing:.6px}}
.f-sec p{{margin-top:3px;color:#c9d4de}}
.f-meta td{{padding:2px 12px 2px 0;border:none;font-size:12.5px}}
.f-meta .k{{color:var(--mut);text-transform:uppercase;font-size:10.5px}}
.kev-yes{{color:#f85149;font-weight:700}}
.mitre-tag{{display:inline-block;background:rgba(79,143,247,.15);color:#4f8ff7;padding:1px 6px;border-radius:4px;font-size:10px;font-family:ui-monospace,monospace}}
.risk-cell{{font-weight:700}}
a{{color:var(--ac);text-decoration:none}}
ul.subs{{columns:3;font-size:12px;color:#a8b7c6;list-style:none;padding:0}}
ul.subs li{{padding:2px 0;break-inside:avoid}}
@media print{{body{{background:#fff;color:#111}} .finding,.kpi{{border-color:#ddd;background:#fff}} h2{{color:#333}}}}
</style></head><body>
<h1>🛡 Attack Surface Report</h1>
<div class="meta">Target: <b class="mono">{_esc(domain)}</b> &nbsp;·&nbsp; Generated: {now} &nbsp;·&nbsp;
Overall Risk: <b style="color:{donut_colors.get(level.lower(), '#e6edf3')}">{level} ({score}/100)</b></div>

<h2>1 · Executive Summary</h2>
<div class="sum-grid">
 <div class="donut"><b>{score}</b></div>
 <div class="legend">
  <div><i style="background:{donut_colors['critical']}"></i>Critical — <b>{counts['critical']}</b></div>
  <div><i style="background:{donut_colors['high']}"></i>High — <b>{counts['high']}</b></div>
  <div><i style="background:{donut_colors['medium']}"></i>Medium — <b>{counts['medium']}</b></div>
  <div><i style="background:{donut_colors['low']}"></i>Low — <b>{counts['low']}</b></div>
  <div><i style="background:{donut_colors['info']}"></i>Info — <b>{counts['info']}</b></div>
  <div class="muted" style="margin-top:8px">{len(live_hosts)} live hosts · {len(subs)} subdomains · {total} findings</div>
 </div>
</div>

<h2>2 · Findings</h2>
{''.join(cards) if cards else '<div class="muted">No findings recorded.</div>'}

<h2>3 · CVE Intelligence (EPSS · CISA KEV · Exploit-DB · Metasploit · MITRE ATT&CK)</h2>
<table><thead><tr><th>CVE</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Context Risk</th><th>Exploit-DB</th><th>Metasploit</th><th>MITRE</th></tr></thead>
<tbody>{cve_rows or '<tr><td colspan="8" class="muted">No CVEs mapped for this scan.</td></tr>'}</tbody></table>

<h2>4 · Host Inventory</h2>
<table><thead><tr><th>Host</th><th>IP</th><th>Protocol</th></tr></thead>
<tbody>{host_rows or '<tr><td colspan="3" class="muted">No live hosts confirmed.</td></tr>'}</tbody></table>

<h2>5 · Subdomains ({len(subs)})</h2>
<ul class="subs">{subs_html or '<li>—</li>'}</ul>

<div class="meta" style="margin-top:30px;border-top:1px solid var(--bd);padding-top:12px">
Generated by attack-surface · Authorized testing only · Findings are point-in-time observations.
</div>
</body></html>"""

    with open(out_path, "w") as f:
        f.write(_HTML)
    return out_path