"""Red Team Report — Professional red team engagement report generator."""

from __future__ import annotations
import json
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class RedTeamFinding:
    """Red team finding."""
    id: str
    title: str
    severity: str  # low, medium, high, critical
    category: str
    target: str
    description: str
    evidence: str
    impact: str
    remediation: str
    tool_used: str
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    cvss_score: float = 0.0
    cve_ids: list[str] = field(default_factory=list)


@dataclass
class TTPMapping:
    """MITRE ATT&CK TTP mapping."""
    tactic: str
    technique_id: str
    technique_name: str
    evidence: list[str]
    count: int


class RedTeamReport:
    """Professional red team engagement report generator."""

    def __init__(self):
        self._findings: list[RedTeamFinding] = []
        self._ttps: list[TTPMapping] = []
        self._scope: dict[str, Any] = {}
        self._executive_summary: str = ""
        self._engagement_info: dict[str, Any] = {}

    def set_engagement_info(
        self,
        client: str,
        team: str,
        start_date: str,
        end_date: str,
        scope: str,
        methodology: str = "PTES / OWASP / MITRE ATT&CK",
    ):
        """Set engagement metadata."""
        self._engagement_info = {
            "client": client,
            "team": team,
            "start_date": start_date,
            "end_date": end_date,
            "scope": scope,
            "methodology": methodology,
        }

    def set_scope(self, targets: list[str], exclusions: list[str] = None):
        """Set engagement scope."""
        self._scope = {
            "included_targets": targets,
            "excluded_targets": exclusions or [],
            "total_targets": len(targets),
        }

    def add_finding(
        self,
        title: str,
        severity: str,
        category: str,
        target: str,
        description: str,
        evidence: str = "",
        impact: str = "",
        remediation: str = "",
        tool_used: str = "",
        mitre_tactics: Optional[list[str]] = None,
        mitre_techniques: Optional[list[str]] = None,
        cvss_score: float = 0.0,
        cve_ids: Optional[list[str]] = None,
    ) -> RedTeamFinding:
        """Add a finding to the report."""
        fid = hashlib.md5(f"{title}:{target}".encode()).hexdigest()[:8]
        finding = RedTeamFinding(
            id=f"RT-{fid}",
            title=title,
            severity=severity,
            category=category,
            target=target,
            description=description,
            evidence=evidence,
            impact=impact,
            remediation=remediation,
            tool_used=tool_used,
            mitre_tactics=mitre_tactics or [],
            mitre_techniques=mitre_techniques or [],
            cvss_score=cvss_score,
            cve_ids=cve_ids or [],
        )
        self._findings.append(finding)
        return finding

    def add_ttp(
        self,
        tactic: str,
        technique_id: str,
        technique_name: str,
        evidence: list[str],
    ):
        """Add a TTP mapping."""
        existing = next(
            (t for t in self._ttps if t.technique_id == technique_id), None
        )
        if existing:
            existing.evidence.extend(evidence)
            existing.count += 1
        else:
            self._ttps.append(TTPMapping(
                tactic=tactic,
                technique_id=technique_id,
                technique_name=technique_name,
                evidence=evidence,
                count=1,
            ))

    def get_statistics(self) -> dict[str, Any]:
        """Get report statistics."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        category_counts: dict[str, int] = {}
        for f in self._findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            category_counts[f.category] = category_counts.get(f.category, 0) + 1

        return {
            "total_findings": len(self._findings),
            "severity_counts": severity_counts,
            "category_counts": category_counts,
            "total_ttps": len(self._ttps),
            "risk_score": self._calculate_risk_score(),
            "risk_level": self._calculate_risk_level(),
        }

    def _calculate_risk_score(self) -> float:
        """Calculate overall risk score."""
        if not self._findings:
            return 0.0
        weights = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 5}
        total = sum(weights.get(f.severity, 0) for f in self._findings)
        max_possible = len(self._findings) * 100
        return min(100, (total / max_possible) * 100) if max_possible > 0 else 0

    def _calculate_risk_level(self) -> str:
        """Calculate risk level from score."""
        score = self._calculate_risk_score()
        if score >= 80:
            return "Critical"
        elif score >= 60:
            return "High"
        elif score >= 40:
            return "Medium"
        elif score >= 20:
            return "Low"
        return "Informational"

    def generate_executive_summary(self) -> str:
        """Generate executive summary."""
        stats = self.get_statistics()
        summary = (
            f"This red team engagement was conducted against {self._scope.get('total_targets', 0)} "
            f"target(s) over the period of {self._engagement_info.get('start_date', 'N/A')} to "
            f"{self._engagement_info.get('end_date', 'N/A')}.\n\n"
            f"The engagement identified {stats['total_findings']} security findings:\n"
            f"- Critical: {stats['severity_counts']['critical']}\n"
            f"- High: {stats['severity_counts']['high']}\n"
            f"- Medium: {stats['severity_counts']['medium']}\n"
            f"- Low: {stats['severity_counts']['low']}\n\n"
            f"Overall Risk Score: {stats['risk_score']:.1f}/100 ({stats['risk_level']})\n\n"
            f"The assessment utilized techniques from the MITRE ATT&CK framework, "
            f"covering {stats['total_ttps']} unique techniques across multiple tactics."
        )
        self._executive_summary = summary
        return summary

    # ==================== REPORT GENERATION ====================

    def generate_json(self) -> dict[str, Any]:
        """Generate full report as JSON."""
        return {
            "engagement": self._engagement_info,
            "scope": self._scope,
            "statistics": self.get_statistics(),
            "executive_summary": self._executive_summary or self.generate_executive_summary(),
            "findings": [vars(f) for f in self._findings],
            "ttps": [vars(t) for t in self._ttps],
            "generated_at": datetime.now().isoformat(),
            "tool": "AttackSurface Scanner v0.21.0 Red Team",
        }

    def generate_markdown(self) -> str:
        """Generate full report as Markdown."""
        lines = []
        lines.append("# Red Team Engagement Report")
        lines.append("")
        lines.append("## Engagement Information")
        for k, v in self._engagement_info.items():
            lines.append(f"- **{k.replace('_', ' ').title()}**: {v}")
        lines.append("")
        lines.append("## Scope")
        for t in self._scope.get("included_targets", []):
            lines.append(f"- {t}")
        lines.append("")
        lines.append("## Executive Summary")
        lines.append(self.generate_executive_summary())
        lines.append("")
        lines.append("## Findings")

        for sev in ["critical", "high", "medium", "low", "info"]:
            findings = [f for f in self._findings if f.severity == sev]
            if findings:
                lines.append(f"\n### {sev.upper()} Findings ({len(findings)})")
                for f in findings:
                    lines.append(f"\n#### {f.id}: {f.title}")
                    lines.append(f"- **Target**: {f.target}")
                    lines.append(f"- **Category**: {f.category}")
                    lines.append(f"- **Description**: {f.description}")
                    if f.evidence:
                        lines.append(f"- **Evidence**: {f.evidence}")
                    if f.impact:
                        lines.append(f"- **Impact**: {f.impact}")
                    if f.remediation:
                        lines.append(f"- **Remediation**: {f.remediation}")
                    if f.tool_used:
                        lines.append(f"- **Tool Used**: {f.tool_used}")
                    if f.cve_ids:
                        lines.append(f"- **CVEs**: {', '.join(f.cve_ids)}")
                    if f.mitre_techniques:
                        lines.append(f"- **MITRE**: {', '.join(f.mitre_techniques)}")

        lines.append("\n## MITRE ATT&CK TTPs")
        for ttp in self._ttps:
            lines.append(f"- **{ttp.technique_id}** ({ttp.technique_name}): {ttp.count} occurrence(s)")
            for ev in ttp.evidence[:3]:
                lines.append(f"  - {ev}")

        lines.append(f"\n---\n*Generated by AttackSurface Scanner v0.21.0 Red Team*")
        return "\n".join(lines)

    def generate_html(self) -> str:
        """Generate full report as HTML."""
        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8",
        }
        stats = self.get_statistics()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Red Team Report — {self._engagement_info.get('client', 'Target')}</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #0a0a0a; color: #e0e0e0; }}
h1 {{ color: #ff4444; border-bottom: 3px solid #ff4444; padding-bottom: 10px; }}
h2 {{ color: #ff6666; margin-top: 30px; }}
h3 {{ color: #ff8888; }}
.severity-badge {{ padding: 3px 10px; border-radius: 4px; color: white; font-weight: bold; font-size: 0.85em; }}
.sev-critical {{ background: #dc3545; }}
.sev-high {{ background: #fd7e14; }}
.sev-medium {{ background: #ffc107; color: #000; }}
.sev-low {{ background: #28a745; }}
.finding {{ background: #1a1a2e; border: 1px solid #333; padding: 15px; margin: 10px 0; border-radius: 8px; }}
.stat-box {{ display: inline-block; width: 150px; text-align: center; padding: 15px; margin: 5px; background: #1a1a2e; border-radius: 8px; border: 1px solid #333; }}
.stat-num {{ font-size: 2em; font-weight: bold; color: #ff4444; }}
table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
th, td {{ padding: 8px 12px; border: 1px solid #333; text-align: left; }}
th {{ background: #1a1a2e; color: #ff6666; }}
pre {{ background: #111; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 0.85em; }}
</style>
</head>
<body>
<h1>Red Team Engagement Report</h1>
<h2>Engagement Information</h2>
<table>
<tr><th>Client</th><td>{self._engagement_info.get('client', 'N/A')}</td></tr>
<tr><th>Team</th><td>{self._engagement_info.get('team', 'N/A')}</td></tr>
<tr><th>Period</th><td>{self._engagement_info.get('start_date', 'N/A')} to {self._engagement_info.get('end_date', 'N/A')}</td></tr>
<tr><th>Methodology</th><td>{self._engagement_info.get('methodology', 'N/A')}</td></tr>
</table>

<h2>Risk Overview</h2>
<div style="text-align:center;">
<div class="stat-box"><div class="stat-num" style="color:#dc3545;">{stats['severity_counts']['critical']}</div>Critical</div>
<div class="stat-box"><div class="stat-num" style="color:#fd7e14;">{stats['severity_counts']['high']}</div>High</div>
<div class="stat-box"><div class="stat-num" style="color:#ffc107;">{stats['severity_counts']['medium']}</div>Medium</div>
<div class="stat-box"><div class="stat-num" style="color:#28a745;">{stats['severity_counts']['low']}</div>Low</div>
<div class="stat-box"><div class="stat-num">{stats['risk_score']:.0f}</div>Risk Score</div>
</div>

<h2>Findings</h2>
"""
        for sev in ["critical", "high", "medium", "low", "info"]:
            findings = [f for f in self._findings if f.severity == sev]
            if findings:
                html += f"<h3>{sev.upper()} ({len(findings)})</h3>\n"
                for f in findings:
                    html += f"""<div class="finding">
<strong>{f.id}: {f.title}</strong> <span class="severity-badge sev-{f.severity}">{f.severity.upper()}</span><br>
<strong>Target:</strong> {f.target} | <strong>Category:</strong> {f.category}<br>
<p>{f.description}</p>
{f'<strong>Evidence:</strong><pre>{f.evidence}</pre>' if f.evidence else ''}
{f'<strong>Impact:</strong> {f.impact}' if f.impact else ''}
{f'<strong>Remediation:</strong> {f.remediation}' if f.remediation else ''}
{f'<strong>Tool:</strong> {f.tool_used}' if f.tool_used else ''}
{f'<strong>MITRE:</strong> {", ".join(f.mitre_techniques)}' if f.mitre_techniques else ''}
</div>\n"""

        html += "<h2>MITRE ATT&CK Coverage</h2>\n<table><tr><th>Technique</th><th>Name</th><th>Hits</th></tr>\n"
        for ttp in sorted(self._ttps, key=lambda t: t.count, reverse=True):
            html += f"<tr><td>{ttp.technique_id}</td><td>{ttp.technique_name}</td><td>{ttp.count}</td></tr>\n"
        html += "</table>\n"

        html += f"\n<hr><p><em>Generated by AttackSurface Scanner v0.21.0 Red Team — {datetime.now().isoformat()}</em></p>\n</body></html>"
        return html

    def export_all(self) -> dict[str, Any]:
        """Export report in all formats."""
        return {
            "json": self.generate_json(),
            "markdown": self.generate_markdown(),
            "html": self.generate_html(),
            "statistics": self.get_statistics(),
        }
