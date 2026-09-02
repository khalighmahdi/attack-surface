# modules/report.py

import html as _html
import logging
import json
from datetime import datetime, timezone
from typing import Dict, Any


def esc(value) -> str:
    """HTML-escape any value before interpolation into the report."""
    return _html.escape(str(value if value is not None else ""), quote=True)


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s - %(message)s",
)


def generate_html_report(results: Dict[str, Any]) -> None:
    """
    Generates an HTML report from attack-surface scan results.
    Schema-aware (v0.3.x)
    """
    logging.info("Generating HTML report...")

    meta = results.get("meta", {})
    discovery = results.get("discovery", {})
    network = results.get("network", {})
    analysis = results.get("analysis", {})

    target = meta.get("target", "unknown")

    timestamp = meta.get("scan_time")
    if timestamp:
        try:
            scan_date = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            ).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            scan_date = timestamp
    else:
        scan_date = "N/A"

    # Ensure reports/html exists
    import os
    os.makedirs("reports/html", exist_ok=True)

    report_filename = (
        f"reports/html/report_{target}_"
        f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.html"
    )
    # remember for callers (runner summary / tests)
    globals()["LAST_REPORT_PATH"] = report_filename

    # ---------- Risk ----------
    risk = analysis.get("risk", {})
    score = risk.get("score", 0)

    if score >= 75:
        score_color = "red"
    elif score >= 40:
        score_color = "orange"
    else:
        score_color = "green"

    html = []

    # ---------- HTML HEADER ----------
    html.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Attack Surface Scan Report – {esc(target)}</title>
<style>
body {{
    font-family: Arial, sans-serif;
    background-color: #f4f4f4;
    margin: 20px;
    color: #333;
}}
.container {{
    max-width: 1200px;
    margin: auto;
    background: #ffffff;
    padding: 20px;
    border-radius: 8px;
}}
h1, h2, h3 {{
    color: #003366;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 20px;
}}
th, td {{
    border: 1px solid #ddd;
    padding: 8px;
}}
th {{
    background-color: #f0f0f0;
}}
pre {{
    background: #eee;
    padding: 10px;
    overflow-x: auto;
}}
.risk-score {{
    font-size: 2em;
    font-weight: bold;
    color: {score_color};
}}
.issues {{
    color: darkred;
}}
</style>
</head>
<body>
<div class="container">
""")

    # ---------- META ----------
    html.append(f"""
<h1>Attack Surface Scan Report</h1>
<p><strong>Target:</strong> {target}</p>
<p><strong>Scan Date:</strong> {scan_date}</p>
<p><strong>Tool Version:</strong> {esc(meta.get('version', 'N/A'))}</p>
<p><strong>Environment:</strong> {esc(meta.get('environment', 'N/A'))}</p>
<h2>Overall Risk Score: <span class="risk-score">{score}</span></h2>
""")

    # ---------- Risk Details ----------
    html.append("<h3>Risk Details</h3>")
    details = risk.get("details", {})

    if details:
        html.append("<ul>")
        for domain, issues in details.items():
            html.append(
                f"<li><strong>{domain}</strong>: {', '.join(issues)}</li>"
            )
        html.append("</ul>")
    else:
        html.append("<p>No risk details available.</p>")

    # ---------- Discovery ----------
    html.append("<h2>Discovery</h2>")
    html.append("<h3>Alive Hosts</h3>")

    alive = discovery.get("alive_hosts", [])
    if alive:
        html.append("<ul>")
        for h in alive:
            html.append(
                f"<li>{esc(h.get('domain'))} "
                f"(IP: {esc(h.get('ip', 'N/A'))}, "
                f"Protocol: {h.get('protocol', 'N/A')})</li>"
            )
        html.append("</ul>")
    else:
        html.append("<p>No alive hosts detected.</p>")

    # ---------- Network / Ports ----------
    html.append("<h2>Network – Port Scan Results</h2>")
    ports = network.get("ports", {})

    if ports:
        html.append("""
<table>
<thead>
<tr><th>Domain</th><th>Open Ports</th></tr>
</thead>
<tbody>
""")
        for domain, data in ports.items():
            port_text = ""
            if data.get("open_ports"):
                port_text = "<br>".join(
                    f"{esc(p.get('port'))}/{esc(p.get('service', 'unknown'))}"
                    for p in data["open_ports"]
                )
            elif data.get("error"):
                port_text = f"Error: {data['error']}"

            html.append(
                f"<tr><td>{domain}</td><td>{port_text}</td></tr>"
            )
        html.append("</tbody></table>")
    else:
        html.append("<p>No port scan data available.</p>")

    # ---------- Technologies ----------
    html.append("<h2>Analysis – Technology Fingerprinting</h2>")
    tech = analysis.get("technologies", {})

    if tech:
        html.append("""
<table>
<thead>
<tr><th>Domain</th><th>URL</th><th>Status</th><th>Technologies</th></tr>
</thead>
<tbody>
""")
        for domain, data in tech.items():
            techs = (
                ", ".join(data["technologies"])
                if data.get("technologies")
                else data.get("error", "")
            )

            html.append(
                f"<tr><td>{domain}</td>"
                f"<td>{esc(data.get('url', 'N/A'))}</td>"
                f"<td>{esc(data.get('status_code', 'N/A'))}</td>"
                f"<td>{techs}</td></tr>"
            )
        html.append("</tbody></table>")
    else:
        html.append("<p>No technology fingerprinting data.</p>")

    # ---------- Headers ----------
    html.append("<h2>Analysis – Header Audit</h2>")
    headers = analysis.get("headers", {})

    if headers:
        html.append("""
<table>
<thead>
<tr><th>Domain</th><th>Status</th><th>Issues</th><th>All Headers</th></tr>
</thead>
<tbody>
""")
        for domain, data in headers.items():
            issues_html = ""
            if data.get("issues"):
                issues_html = "<ul>" + "".join(
                    f"<li>{i}</li>" for i in data["issues"]
                ) + "</ul>"

            html.append(
                f"<tr><td>{domain}</td>"
                f"<td>{esc(data.get('status_code', 'N/A'))}</td>"
                f"<td class='issues'>{issues_html}</td>"
                f"<td><pre>{esc(json.dumps(data.get('all_headers', {}), indent=2))}</pre></td>"
                f"</tr>"
            )
        html.append("</tbody></table>")
    else:
        html.append("<p>No header audit data available.</p>")

    # ---------- Primary Admin Panels ----------
    primary = analysis.get("primary_admin_panels", [])
    if primary:
        html.append("<h2>🎯 Primary Admin Panels (auto-detected)</h2>")
        html.append("<p>These are the panels most likely to actually control the server "
                    "(cPanel, WHM, Plesk, ...), ranked by an internal score. "
                    "Lower-priority hits (user-facing login forms, redirects) are filtered out.</p>")
        html.append("""
<table>
<thead>
<tr><th>Host</th><th>URL</th><th>Vendor</th><th>Score</th><th>Protected</th><th>Notes</th></tr>
</thead>
<tbody>
""")
        for p in primary:
            notes = []
            if p.get("cross_host_redirect"):
                notes.append("Cross-host redirect")
            if not p.get("protected"):
                notes.append("Unprotected (no 401/403 challenge)")
            notes_html = "<br>".join(notes) if notes else "—"
            protected_html = ("✅ Yes" if p.get("protected") else "❌ No")
            vendor = p.get("vendor") or "Unknown"
            html.append(
                f"<tr>"
                f"<td><strong>{esc(p.get('domain', 'N/A'))}</strong></td>"
                f"<td><a href='{esc(p.get('url', '#'))}'>{esc(p.get('url', 'N/A'))}</a></td>"
                f"<td>{vendor}</td>"
                f"<td>{esc(p.get('score', 0))}</td>"
                f"<td>{protected_html}</td>"
                f"<td>{notes_html}</td>"
                f"</tr>"
            )
        html.append("</tbody></table>")
    else:
        html.append("<h2>🎯 Primary Admin Panels</h2>")
        html.append("<p>No high-confidence primary admin panel detected.</p>")

    # ---------- All admin panels (for completeness) ----------
    # ---------- Takeover risks ----------
    takeovers = analysis.get("takeover_risks", []) or []
    if takeovers:
        html.append("<h2>☠️ Possible Subdomain Takeover (CRITICAL)</h2>")
        html.append("<table><thead><tr><th>Host</th><th>Service</th><th>Evidence</th></tr></thead><tbody>")
        for t in takeovers:
            html.append(
                f"<tr><td><strong>{esc(t.get('host'))}</strong></td>"
                f"<td>{esc(t.get('service'))}</td>"
                f"<td>{esc(t.get('evidence_url'))}</td></tr>"
            )
        html.append("</tbody></table>")

    # ---------- Blue-team diff ----------
    bdiff = analysis.get("blue_team_diff", {}) or {}
    if any(bdiff.values()):
        html.append("<h2>🛡 Attack-Surface Changes Since Last Scan</h2>")
        labels = {"NEW_HOSTS": "🟢 New hosts", "GONE_HOSTS": "🔴 Gone hosts",
                  "NEW_OPEN_PORTS": "🟠 Newly opened ports",
                  "CLOSED_PORTS": "⚪ Closed ports",
                  "NEW_ADMIN_PANELS": "🟠 New admin panels",
                  "NEW_SETUP_PAGES": "🚨 New setup pages",
                  "RISK_DELTA": "📉 Risk score changes"}
        for key, title in labels.items():
            items = bdiff.get(key) or []
            if not items:
                continue
            html.append(f"<h3>{title} ({len(items)})</h3><ul>")
            for it in items[:30]:
                if isinstance(it, dict):
                    html.append(f"<li>{esc(json.dumps(it, ensure_ascii=False))}</li>")
                else:
                    html.append(f"<li>{esc(it)}</li>")
            html.append("</ul>")

    # ---------- CVE watchlist ----------
    cves = analysis.get("cve_watchlist", {}) or {}
    if cves:
        html.append("<h2>🔎 CVE Watchlist (NVD, CVSS ≥ High)</h2>")
        html.append("<table><thead><tr><th>Host</th><th>Technology</th><th>CVEs</th></tr></thead><tbody>")
        for host, entries in cves.items():
            for e in entries:
                ids = ", ".join(
                    f"{c.get('id')} ({c.get('cvss', '?')})" for c in e.get("cves", [])[:6]
                )
                html.append(
                    f"<tr><td>{esc(host)}</td><td>{esc(e.get('tech'))}</td>"
                    f"<td>{esc(ids)}</td></tr>"
                )
        html.append("</tbody></table>")

    # ---------- Exposed CMS setup pages (CRITICAL) ----------
    setup_pages = analysis.get("setup_pages", {}) or {}
    if setup_pages:
        html.append("<h2>🚨 Exposed CMS Setup Pages (CRITICAL)</h2>")
        html.append("<p>The CMS is <strong>half-installed</strong> — anyone can complete the setup and take over the site. Fix immediately.</p>")
        html.append("<table><thead><tr><th>Host</th><th>CMS</th><th>URL</th><th>Status</th></tr></thead><tbody>")
        for host, pages in setup_pages.items():
            for pg in pages:
                html.append(
                    f"<tr><td><strong>{esc(host)}</strong></td>"
                    f"<td>{esc(pg.get('cms', '?'))}</td>"
                    f"<td><a href='{esc(pg.get('url', '#'))}'>{esc(pg.get('url', 'N/A'))}</a></td>"
                    f"<td>{esc(pg.get('status_code', 'N/A'))}</td></tr>"
                )
        html.append("</tbody></table>")

    all_panels = analysis.get("admin_panels", {})
    if all_panels:
        html.append("<h3>All admin/login endpoints found</h3>")
        html.append("""
<table>
<thead>
<tr><th>Host</th><th>Path</th><th>Status</th><th>Type</th><th>URL</th></tr>
</thead>
<tbody>
""")
        for host, panels in all_panels.items():
            for p in panels:
                primary_mark = " 🎯" if p.get("is_primary") else ""
                html.append(
                    f"<tr>"
                    f"<td>{host}</td>"
                    f"<td>{esc(p.get('path', 'N/A'))}{primary_mark}</td>"
                    f"<td>{esc(p.get('status_code', 'N/A'))}</td>"
                    f"<td>{esc(p.get('panel_type', 'unknown'))}</td>"
                    f"<td>{esc(p.get('url', 'N/A'))}</td>"
                    f"</tr>"
                )
        html.append("</tbody></table>")

    # ---------- FOOTER ----------
    html.append("</div></body></html>")

    # ---------- WRITE ----------
    try:
        with open(report_filename, "w", encoding="utf-8") as f:
            f.write("\n".join(html))
        logging.info("HTML report generated: %s", report_filename)
        return report_filename
    except IOError as e:
        logging.error("Failed to write HTML report: %s", e)
        return ""

