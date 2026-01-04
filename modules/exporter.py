# modules/exporter.py
import csv
import os
from datetime import datetime

# -------------------------
# Helper
# -------------------------
def _safe_get(d, *keys, default=None):
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k)
    return d if d is not None else default


# -------------------------
# CSV Export
# -------------------------
def export_csv(data: dict, output_path: str):
    """
    Export summarized findings to CSV
    """
    fields = [
        "host",
        "risk_level",
        "risk_score",
        "open_ports",
        "technologies",
        "misconfigurations",
        "findings"
    ]

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for host in data.get("alive_hosts", []):
            risk = _safe_get(data, "risk_scores", host, default={})
            findings = _safe_get(data, "findings", host, default=[])
            ports = _safe_get(data, "ports", host, default=[])
            tech = _safe_get(data, "technologies", host, default={})
            misconf = _safe_get(data, "misconfigurations", host, default={})

            writer.writerow({
                "host": host,
                "risk_level": risk.get("level", "unknown"),
                "risk_score": risk.get("score", 0),
                "open_ports": ",".join(str(p["port"]) for p in ports),
                "technologies": ",".join(tech) if isinstance(tech, list) else "",
                "misconfigurations": ",".join(
                    misconf.get("missing", []) + misconf.get("info_leaks", [])
                ),
                "findings": "; ".join(findings)
            })


# -------------------------
# Markdown Export
# -------------------------
def export_markdown(data: dict, output_path: str):
    """
    Export full report in Markdown format
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    md = []
    meta = data.get("metadata", {})

    md.append(f"# Attack Surface Report – {meta.get('target', '')}")
    md.append(f"- **Scan Date:** {meta.get('scan_date')}")
    md.append(f"- **Tool Version:** {meta.get('version')}\n")

    for host in data.get("alive_hosts", []):
        md.append(f"## {host}")

        # Risk
        risk = data.get("risk_scores", {}).get(host, {})
        md.append(f"**Risk Level:** `{risk.get('level', 'unknown')}`")
        md.append(f"**Risk Score:** `{risk.get('score', 0)}`\n")

        # Ports
        ports = data.get("ports", {}).get(host, [])
        if ports:
            md.append("### Open Ports")
            for p in ports:
                md.append(
                    f"- `{p['port']}/{p['proto']}` – {p['service']} {p.get('version','')}"
                )

        # Technologies
        tech = data.get("technologies", {}).get(host, [])
        if tech:
            md.append("\n### Detected Technologies")
            for t in tech:
                md.append(f"- {t}")

        # Misconfigs
        mis = data.get("misconfigurations", {}).get(host, {})
        if mis:
            md.append("\n### Misconfigurations")
            for k, v in mis.items():
                for item in v:
                    md.append(f"- **{k}**: {item}")

        # Findings
        findings = data.get("findings", {}).get(host, [])
        if findings:
            md.append("\n### Findings")
            for f in findings:
                md.append(f"- {f}")

        md.append("\n---\n")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md))

