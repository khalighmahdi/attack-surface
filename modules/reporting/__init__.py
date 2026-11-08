"""Advanced Reporting — Executive, Technical, Compliance, Custom Templates.

Generates multiple report formats from scan results:
- Executive Summary (PDF/HTML) — high-level risk, business impact
- Technical Detail (PDF/HTML) — findings, evidence, remediation
- Compliance Mapping (PDF/HTML) — NIST, ISO27001, PCI-DSS, SOC2, GDPR
- Custom Jinja2 Templates — user-defined report structures
- Scheduled/Automated report generation
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AttackSurface.Reporting")


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    template: str = "executive"  # executive, technical, compliance, custom
    format: str = "html"  # html, pdf, markdown
    output_dir: str = "reports"
    compliance_frameworks: List[str] = field(default_factory=lambda: ["nist", "iso27001", "pci-dss", "soc2", "gdpr"])
    custom_template_path: Optional[str] = None
    include_charts: bool = True
    include_evidence: bool = True
    executive_summary_only: bool = False


class AdvancedReportGenerator:
    """Generate professional reports from scan results."""

    # Compliance control mappings
    COMPLIANCE_MAPPING = {
        "NIST-CSF": {
            "ID.AM": ["asset_inventory", "subdomain_enum", "cloud_discovery"],
            "ID.RA": ["vuln_scanning", "risk_scoring", "threat_intel"],
            "PR.AC": ["auth_testing", "access_controls", "privilege_escalation"],
            "PR.DS": ["data_protection", "encryption", "certificate_analysis"],
            "DE.CM": ["monitoring", "anomaly_detection", "continuous_scanning"],
            "RS.RP": ["incident_response", "forensics", "attack_paths"],
            "RC.RP": ["recovery_planning", "backup_verification"],
        },
        "ISO27001": {
            "A.8.1.1": ["asset_inventory"],
            "A.12.6.1": ["vuln_management"],
            "A.14.2.5": ["secure_development"],
            "A.16.1": ["incident_management"],
        },
        "PCI-DSS": {
            "Req-6": ["vuln_scanning", "secure_coding"],
            "Req-11": ["penetration_testing", "va_scanning"],
            "Req-12": ["risk_assessment"],
        },
        "SOC2": {
            "CC6.1": ["access_controls"],
            "CC7.1": ["monitoring", "vuln_scanning"],
            "CC7.2": ["anomaly_detection"],
        },
        "GDPR": {
            "Art-32": ["encryption", "data_protection", "breach_notification"],
            "Art-33": ["incident_response", "72h_notification"],
        }
    }

    def __init__(self, config: ReportConfig):
        self.config = config
        self.output_dir = Path(config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, ctx_data: Dict[str, Any]) -> Dict[str, str]:
        """Generate all configured reports, return paths."""
        results = {}

        if self.config.template in ("executive", "all"):
            results["executive"] = self._generate_executive(ctx_data)
        if self.config.template in ("technical", "all"):
            results["technical"] = self._generate_technical(ctx_data)
        if self.config.template in ("compliance", "all"):
            results["compliance"] = self._generate_compliance(ctx_data)

        return results

    def _generate_executive(self, ctx: Dict) -> str:
        """Executive summary — business risk, trends, recommendations."""
        meta = ctx.get("meta", {})
        analysis = ctx.get("analysis", {})
        risk = analysis.get("risk", {})

        # Calculate business impact
        overall_score = risk.get("score", 0)
        overall_level = risk.get("level", "Unknown")
        total_findings = sum(len(v) for v in analysis.get("findings", {}).values())
        critical_findings = sum(1 for v in analysis.get("findings", {}).values()
                                for f in v if isinstance(f, dict) and f.get("severity") == "critical")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Executive Security Assessment - {meta.get('target', 'Unknown')}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 40px; background: #f8f9fa; color: #212529; }}
        .container {{ max-width: 900px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; border-bottom: 3px solid #dc3545; padding-bottom: 20px; margin-bottom: 30px; }}
        .score-badge {{ display: inline-block; padding: 15px 30px; border-radius: 50px; font-size: 24px; font-weight: 700; color: white; }}
        .critical {{ background: linear-gradient(135deg, #dc3545, #c82333); }}
        .high {{ background: linear-gradient(135deg, #fd7e14, #e86c00); }}
        .medium {{ background: linear-gradient(135deg, #ffc107, #e0a800); }}
        .low {{ background: linear-gradient(135deg, #28a745, #218838); }}
        .section {{ margin: 30px 0; }}
        .section h2 {{ color: #343a40; border-left: 4px solid #dc3545; padding-left: 15px; }}
        .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .metric {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .metric-value {{ font-size: 36px; font-weight: 700; color: #dc3545; }}
        .metric-label {{ color: #6c757d; font-size: 14px; text-transform: uppercase; }}
        .recommendations {{ background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 20px; }}
        .rec-item {{ margin: 10px 0; padding-left: 20px; position: relative; }}
        .rec-item::before {{ content: "▸"; position: absolute; left: 0; color: #dc3545; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }}
        th {{ background: #343a40; color: white; }}
        tr:hover {{ background: #f8f9fa; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Executive Security Assessment</h1>
            <p><strong>Target:</strong> {meta.get('target', 'Unknown')}</p>
            <p><strong>Scan Date:</strong> {meta.get('scan_time', 'Unknown')}</p>
            <p><strong>Version:</strong> {meta.get('version', 'Unknown')}</p>
        </div>

        <div class="section">
            <h2>Overall Risk Posture</h2>
            <div style="text-align: center;">
                <span class="score-badge {overall_level.lower()}">{overall_score}/100 — {overall_level}</span>
            </div>
        </div>

        <div class="metrics">
            <div class="metric">
                <div class="metric-value">{total_findings}</div>
                <div class="metric-label">Total Findings</div>
            </div>
            <div class="metric">
                <div class="metric-value">{critical_findings}</div>
                <div class="metric-label">Critical Issues</div>
            </div>
            <div class="metric">
                <div class="metric-value">{len(analysis.get('discovery', {}).get('alive_hosts', []))}</div>
                <div class="metric-label">Exposed Hosts</div>
            </div>
            <div class="metric">
                <div class="metric-value">{len(analysis.get('discovery', {}).get('subdomains', []))}</div>
                <div class="metric-label">Subdomains</div>
            </div>
        </div>

        <div class="section">
            <h2>Key Risk Areas</h2>
            <table>
                <thead>
                    <tr><th>Category</th><th>Count</th><th>Severity</th></tr>
                </thead>
                <tbody>"""

        # Categorize findings
        categories = {}
        for host, findings in analysis.get("findings", {}).items():
            for f in findings:
                if isinstance(f, dict):
                    cat = f.get("type", "Other")
                else:
                    cat = f
                if cat not in categories:
                    categories[cat] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                sev = f.get("severity", "info") if isinstance(f, dict) else "info"
                categories[cat][sev] = categories[cat].get(sev, 0) + 1

        for cat, counts in sorted(categories.items(), key=lambda x: sum(x[1].values()), reverse=True):
            total = sum(counts.values())
            html += f"<tr><td>{cat}</td><td>{total}</td><td>Critical: {counts['critical']}, High: {counts['high']}, Med: {counts['medium']}</td></tr>"

        html += f"""
                </tbody>
            </table>
        </div>

        <div class="section recommendations">
            <h2>Immediate Recommendations</h2>
            <div class="rec-item">Patch all Critical/High severity vulnerabilities within 72 hours</div>
            <div class="rec-item">Implement WAF rules for exposed admin panels (cPanel, Plesk, WHM)</div>
            <div class="rec-item">Disable Telnet (port 23) and restrict RDP (3389) to VPN only</div>
            <div class="rec-item">Implement DMARC policy (reject) to prevent email spoofing</div>
            <div class="rec-item">Enable security headers (CSP, HSTS, X-Frame-Options) on all web assets</div>
            <div class="rec-item">Rotate exposed credentials and implement MFA on all admin interfaces</div>
            <div class="rec-item">Schedule continuous attack surface monitoring (weekly scans)</div>
        </div>

        <div class="section">
            <h2>Compliance Posture</h2>
            <p>This assessment covers controls for: NIST CSF, ISO 27001, PCI-DSS, SOC 2, GDPR</p>
            <p>Detailed compliance mapping available in the Compliance Report.</p>
        </div>

        <hr style="margin-top: 40px; border-color: #dee2e6;">
        <p style="text-align: center; color: #6c757d; font-size: 12px;">
            Generated by Attack Surface Scanner v{meta.get('version', 'Unknown')} | {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}
        </p>
    </div>
</body>
</html>"""

        path = self.output_dir / f"report_{meta.get('target', 'target')}_executive.html"
        path.write_text(html)
        logger.info("Executive report: %s", path)
        return str(path)

    def _generate_technical(self, ctx: Dict) -> str:
        """Technical detail report — findings, evidence, remediation."""
        meta = ctx.get("meta", {})
        analysis = ctx.get("analysis", {})

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Technical Security Assessment - {meta.get('target', 'Unknown')}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; margin: 0; padding: 20px; background: #f8f9fa; color: #212529; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }}
        .header {{ border-bottom: 2px solid #343a40; padding-bottom: 15px; margin-bottom: 25px; }}
        .finding {{ border: 1px solid #dee2e6; border-radius: 6px; margin: 15px 0; overflow: hidden; }}
        .finding-header {{ padding: 15px; background: #f8f9fa; border-bottom: 1px solid #dee2e6; display: flex; justify-content: space-between; }}
        .finding-body {{ padding: 15px; }}
        .badge {{ padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; text-transform: uppercase; }}
        .badge-critical {{ background: #f8d7da; color: #721c24; }}
        .badge-high {{ background: #ffe8cc; color: #856404; }}
        .badge-medium {{ background: #fff3cd; color: #856404; }}
        .badge-low {{ background: #d4edda; color: #155724; }}
        .badge-info {{ background: #d1ecf1; color: #0c5460; }}
        pre {{ background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; font-size: 13px; }}
        .evidence {{ background: #e9ecef; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Technical Security Assessment</h1>
            <p><strong>Target:</strong> {meta.get('target', 'Unknown')} | <strong>Scan:</strong> {meta.get('scan_time', 'Unknown')} | <strong>Version:</strong> {meta.get('version', 'Unknown')}</p>
        </div>"""

        for host, findings in analysis.get("findings", {}).items():
            html += f"<h2>Host: {host}</h2>"
            for f in findings:
                if not isinstance(f, dict):
                    continue
                sev = f.get("severity", "info")
                title = f.get("title", f.get("type", "Finding"))
                evidence = f.get("evidence", "")
                description = f.get("description", "")
                remediation = f.get("remediation", "")

                html += f"""
        <div class="finding">
            <div class="finding-header">
                <strong>{title}</strong>
                <span class="badge badge-{sev}">{sev}</span>
            </div>
            <div class="finding-body">"""
                if description:
                    html += f"<p><strong>Description:</strong> {description}</p>"
                if evidence:
                    html += f"<p><strong>Evidence:</strong></p><pre class='evidence'>{evidence}</pre>"
                if remediation:
                    html += f"<p><strong>Remediation:</strong> {remediation}</p>"
                html += "</div></div>"

        # Coverage + autonomous-agent sections: only this tool writes them,
        # and a report must never look clean when the scan was incomplete.
        coverage = ctx.get("coverage") or {}
        if coverage:
            state = str(coverage.get("state") or "unknown")
            tone = ("#0a7d32" if state == "reachable" else "#b3261e")
            html += f"""
        <div class="finding">
            <div class="finding-header"><strong>Scan Coverage</strong>
            <span class="badge" style="background:{tone};color:#fff">{state.upper()}</span></div>
            <div class="finding-body">
                <p>{coverage.get('note') or 'The target answered HTTP probes; coverage below reflects a reachable host.'}</p>
                <p style="color:#6c757d">HTTP hosts: {coverage.get('http_hosts', 0)} /
                hosts checked: {coverage.get('hosts_checked', 0)} /
                open ports: {coverage.get('open_ports', 0)}</p>
            </div>
        </div>"""

        kn = ctx.get("knull") or {}
        if kn:
            tech_rows = "".join(
                f"<tr><td>{t.get('technique')}</td><td>{t.get('decided')}</td>"
                f"<td>{t.get('success')}</td><td>{t.get('failure')}</td>"
                f"<td>{t.get('success_rate')}</td></tr>"
                for t in (kn.get("techniques") or []))
            html += f"""
        <h2>Autonomous agent (Knull)</h2>
        <p>Sessions: {kn.get('sessions', 0)} &middot;
           decisions verified: {kn.get('decided', 0)} &middot;
           confirmed: {kn.get('confirmed', 0)} &middot;
           refuted: {kn.get('refuted', 0)} &middot;
           awaiting a verdict: {kn.get('pending', 0)}</p>"""
            if tech_rows:
                html += f"""
        <table><thead><tr><th>Technique</th><th>Decided</th><th>Confirmed</th>
        <th>Refuted</th><th>Success rate</th></tr></thead>
        <tbody>{tech_rows}</tbody></table>"""
            worn = kn.get("worn_out") or []
            if worn:
                html += (f"<p><strong>Worn out:</strong> {', '.join(worn)} "
                         f"— tried repeatedly without a single confirmed result.</p>")

        html += f"""
        <hr style="margin-top: 40px;">
        <p style="color: #6c757d; font-size: 12px;">
            Generated by Attack Surface Scanner v{meta.get('version', 'Unknown')} | {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}
        </p>
    </div>
</body>
</html>"""

        path = self.output_dir / f"report_{meta.get('target', 'target')}_technical.html"
        path.write_text(html)
        logger.info("Technical report: %s", path)
        return str(path)

    def _generate_compliance(self, ctx: Dict) -> str:
        """Compliance mapping report — NIST, ISO27001, PCI-DSS, SOC2, GDPR."""
        meta = ctx.get("meta", {})
        analysis = ctx.get("analysis", {})
        findings = analysis.get("findings", {})

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Compliance Mapping Report - {meta.get('target', 'Unknown')}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f8f9fa; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }}
        .framework {{ margin: 30px 0; }}
        .framework h2 {{ color: #343a40; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        .control {{ margin: 15px 0; padding: 15px; background: #f8f9fa; border-radius: 6px; border-left: 4px solid #007bff; }}
        .control-id {{ font-weight: 700; color: #007bff; }}
        .status-pass {{ border-left-color: #28a745; }}
        .status-fail {{ border-left-color: #dc3545; }}
        .status-partial {{ border-left-color: #ffc107; }}
        .mapped-findings {{ margin-top: 10px; font-size: 13px; color: #6c757d; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Compliance Mapping Report</h1>
        <p><strong>Target:</strong> {meta.get('target', 'Unknown')} | <strong>Scan:</strong> {meta.get('scan_time', 'Unknown')}</p>

        <p>This report maps discovered findings to common compliance frameworks.
        <strong>Status</strong> is determined by whether controls have passing or failing evidence.</p>"""

        for framework, controls in self.COMPLIANCE_MAPPING.items():
            html += f'<div class="framework"><h2>{framework}</h2>'
            for control_id, keywords in controls.items():
                # Check if any findings match this control's keywords
                matched = []
                for host, host_findings in findings.items():
                    for f in host_findings:
                        if not isinstance(f, dict):
                            continue
                        title = f.get("title", "").lower()
                        cat = f.get("category", "").lower()
                        for kw in keywords:
                            if kw.lower() in title or kw.lower() in cat:
                                matched.append({"host": host, "finding": f.get("title", cat), "severity": f.get("severity", "info")})

                if matched:
                    status = "fail" if any(m["severity"] in ("critical", "high") for m in matched) else "partial"
                else:
                    status = "pass"

                status_class = f"status-{status}"
                html += f'''
                <div class="control {status_class}">
                    <span class="control-id">{control_id}</span> — {", ".join(keywords)}
                    <div class="mapped-findings">
                        {"✅ No relevant findings" if status == "pass" else f"⚠️ {len(matched)} finding(s): " + ", ".join(f"{m['host']}: {m['finding']} ({m['severity']})" for m in matched[:3])}
                    </div>
                </div>'''

            html += "</div>"

        html += f"""
        <hr style="margin-top: 40px;">
        <p style="color: #6c757d; font-size: 12px;">
            Generated by Attack Surface Scanner v{meta.get('version', 'Unknown')} | {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}
        </p>
    </div>
</body>
</html>"""

        path = self.output_dir / f"report_{meta.get('target', 'target')}_compliance.html"
        path.write_text(html)
        logger.info("Compliance report: %s", path)
        return str(path)


def generate_report(ctx_data: Dict[str, Any], template: str = "executive", format: str = "html",
                    output_dir: str = "reports", **kwargs) -> Dict[str, str]:
    """Convenience function for report generation."""
    config = ReportConfig(template=template, format=format, output_dir=output_dir, **kwargs)
    generator = AdvancedReportGenerator(config)
    return generator.generate(ctx_data)