import logging
import csv
from typing import Dict, Any

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s - %(message)s"
)

# -------------------------------------------------
# CSV Export
# -------------------------------------------------
def export_csv(results: Dict[str, Any], filename: str) -> None:
    """
    Export key scan results to a CSV file.
    Schema-aware (v0.3.x) and safe for automation.
    """
    logging.info("Exporting results to CSV: %s", filename)

    discovery = results.get("discovery", {})
    network = results.get("network", {})
    analysis = results.get("analysis", {})
    risk = analysis.get("risk", {})
    risk_score = risk.get("score", "N/A")

    rows = []

    for host in discovery.get("alive_hosts", []):
        domain = host.get("domain", "N/A")
        ip = host.get("ip", "N/A")

        row = {
            "Domain": domain,
            "IP Address": ip,
            "Status": host.get("status", "N/A"),
            "Protocol": host.get("protocol", "N/A"),
            "Open Ports": "",
            "Technologies": "",
            "Header Issues": "",
            "Overall Risk Score": risk_score,
        }

        # Ports
        port_info = network.get("ports", {}).get(domain, {})
        if port_info.get("open_ports"):
            row["Open Ports"] = ", ".join(
                (f"{p.get('port')}/{p.get('service', 'unknown')}"
                 + (f" ({p['banner']})" if p.get("banner") else ""))
                for p in port_info["open_ports"]
            )
        elif port_info.get("error"):
            row["Open Ports"] = f"Error: {port_info['error']}"

        # Technologies
        tech_info = analysis.get("technologies", {}).get(domain, {})
        if tech_info.get("technologies"):
            row["Technologies"] = ", ".join(tech_info["technologies"])
        elif tech_info.get("error"):
            row["Technologies"] = f"Error: {tech_info['error']}"

        # Header issues
        header_info = analysis.get("headers", {}).get(domain, {})
        if header_info.get("issues"):
            row["Header Issues"] = ", ".join(header_info["issues"])
        elif header_info.get("error"):
            row["Header Issues"] = f"Error: {header_info['error']}"

        rows.append(row)

    if not rows:
        logging.warning("No data available for CSV export.")
        return

    try:
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)

        logging.info("CSV export completed successfully.")

    except Exception as e:
        logging.error("CSV export failed: %s", e)


# -------------------------------------------------
# Markdown Export
# -------------------------------------------------
def export_markdown(results: Dict[str, Any], filename: str) -> None:
    """
    Export scan results to a Markdown report.
    Compatible with engine schema v0.3.x
    """
    logging.info("Exporting results to Markdown: %s", filename)

    meta = results.get("meta", {})
    discovery = results.get("discovery", {})
    network = results.get("network", {})
    analysis = results.get("analysis", {})
    risk = analysis.get("risk", {})

    md = []

    md.append("# Attack Surface Scan Report\n\n")
    md.append(f"**Target:** {meta.get('target', 'N/A')}\n\n")
    md.append(f"**Scan Date:** {meta.get('scan_time', 'N/A')}\n\n")
    md.append(f"**Tool Version:** {meta.get('version', 'N/A')}\n\n")
    md.append(f"**Environment:** {meta.get('environment', 'N/A')}\n\n")

    md.append(f"## Overall Risk Score: {risk.get('score', 'N/A')}\n\n")

    if risk.get("details"):
        md.append("### Risk Details\n\n")
        for domain, issues in risk["details"].items():
            md.append(f"- **{domain}**: {', '.join(issues)}\n")
        md.append("\n")

    # -------------------------
    # Primary Admin Panels (auto-detected)
    # -------------------------
    primary = analysis.get("primary_admin_panels", [])
    if primary:
        md.append("## 🎯 Primary Admin Panels (auto-detected)\n\n")
        md.append("The control panels most likely to actually manage the server "
                  "(cPanel, WHM, Plesk, ...). Lower-priority hits and user "
                  "login forms are filtered out.\n\n")
        md.append("| Host | URL | Vendor | Score | Protected | Notes |\n")
        md.append("|---|---|---|---|---|---|\n")
        for p in primary:
            notes = []
            if p.get("cross_host_redirect"):
                notes.append("cross-host redirect")
            if not p.get("protected"):
                notes.append("unprotected")
            notes_s = ", ".join(notes) if notes else "—"
            protected = "✅ yes" if p.get("protected") else "❌ no"
            vendor = p.get("vendor") or "Unknown"
            md.append(
                f"| {p.get('domain', 'N/A')} "
                f"| {p.get('url', 'N/A')} "
                f"| {vendor} "
                f"| {p.get('score', 0)} "
                f"| {protected} "
                f"| {notes_s} |\n"
            )
        md.append("\n")

    # -------------------------
    # Discovery
    # -------------------------
    md.append("## Discovery\n\n")
    md.append("### Alive Hosts\n\n")

    alive_hosts = discovery.get("alive_hosts", [])
    if alive_hosts:
        for host in alive_hosts:
            md.append(
                f"- {host.get('domain')} "
                f"(IP: {host.get('ip', 'N/A')}, "
                f"Protocol: {host.get('protocol', 'N/A')})\n"
            )
    else:
        md.append("No alive hosts found.\n")

    # -------------------------
    # Ports
    # -------------------------
    md.append("\n## Network – Port Scan Results\n\n")

    ports = network.get("ports")
    if ports:
        md.append("| Domain | Open Ports |\n")
        md.append("|---|---|\n")
        for domain, data in ports.items():
            port_str = ""
            if data.get("open_ports"):
                port_str = ", ".join(
                    f"{p.get('port')}/{p.get('service', 'unknown')}"
                    for p in data["open_ports"]
                )
            elif data.get("error"):
                port_str = f"Error: {data['error']}"

            md.append(f"| {domain} | {port_str} |\n")
    else:
        md.append("No port scan data available.\n")

    # -------------------------
    # Technologies
    # -------------------------
    md.append("\n## Analysis – Technology Fingerprinting\n\n")

    technologies = analysis.get("technologies")
    if technologies:
        md.append("| Domain | URL | Status | Technologies |\n")
        md.append("|---|---|---|---|\n")
        for domain, data in technologies.items():
            tech = ""
            if data.get("technologies"):
                tech = ", ".join(data["technologies"])
            elif data.get("error"):
                tech = f"Error: {data['error']}"

            md.append(
                f"| {domain} | {data.get('url', 'N/A')} | "
                f"{data.get('status_code', 'N/A')} | {tech} |\n"
            )
    else:
        md.append("No technology data available.\n")

    # -------------------------
    # Headers
    # -------------------------
    md.append("\n## Analysis – Header Audit\n\n")

    headers = analysis.get("headers")
    if headers:
        md.append("| Domain | URL | Status | Issues |\n")
        md.append("|---|---|---|---|\n")
        for domain, data in headers.items():
            issues = ""
            if data.get("issues"):
                issues = ", ".join(data["issues"])
            elif data.get("error"):
                issues = f"Error: {data['error']}"

            md.append(
                f"| {domain} | {data.get('url', 'N/A')} | "
                f"{data.get('status_code', 'N/A')} | {issues} |\n"
            )
    else:
        md.append("No header audit data available.\n")

    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.writelines(md)

        logging.info("Markdown export completed successfully.")

    except Exception as e:
        logging.error("Markdown export failed: %s", e)



# -------------------------------------------------
# JSON Export
# -------------------------------------------------
def export_json(results: Dict[str, Any], filename: str) -> None:
    """Full machine-readable report (for CI / dashboards)."""
    import json as _json
    logging.info("Exporting results to JSON: %s", filename)
    with open(filename, "w", encoding="utf-8") as f:
        _json.dump(results, f, ensure_ascii=False, indent=2, default=str)
    logging.info("JSON export completed successfully.")
