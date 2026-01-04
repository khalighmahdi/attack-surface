__version__ = "0.1.0"

import sys
import os
import re
import json
import argparse
import logging
import concurrent.futures
from datetime import datetime

# -------------------------
# Logging Configuration
# -------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("AttackSurface")

# -------------------------
# Path & Config
# -------------------------
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    # Assuming core/config exists based on original code structure
    from core.config import MAX_THREADS
except ImportError:
    MAX_THREADS = 5

# -------------------------
# Internal Modules (Cleaned Imports)
# -------------------------
try:
    # Reporting & Exporting
    from modules.report import export_html
    from modules.exporter import export_csv, export_markdown
    
    # Discovery & Scanning
    from modules.subdomains import enumerate_subdomains
    from modules.alive import check_alive
    from modules.ports import scan_ports
    from modules.headers import fetch_headers

    # Analysis Engines
    from modules.header_audit import scan_headers
    from modules.tech_fingerprint import fingerprint_from_headers
    from modules.risk_scoring import calculate_risk
    from modules.correlation_engine import generate_findings
    
    # Advanced Analysis
    from modules.attack_path_engine import build_attack_paths
    from modules.mitre_mapping import map_attack_paths_to_mitre
    from modules.kill_chain import build_kill_chain
    from modules.graph_builder import build_attack_surface_graph
    
    # Utility
    from modules.updater import check_for_update, apply_update
    
except ImportError as e:
    logger.critical(f"Missing module: {e}")
    sys.exit(1)

# -------------------------
# Utilities
# -------------------------
def parse_nmap_ports(output: str):
    ports = []
    if not output or "Error" in output:
        return ports

    # Regex fixed for better capture consistency
    regex = r"(\d+)\/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?"

    for line in output.splitlines():
        if "PORT" in line or "Starting Nmap" in line:
            continue

        match = re.search(regex, line.strip())
        if match:
            ports.append({
                "port": int(match.group(1)),
                "proto": match.group(2),
                "service": match.group(3),
                "version": match.group(4).strip() if match.group(4) else "",
                "state": "open"
            })

    return ports

# -------------------------
# Thread Workers
# -------------------------
def process_port_scan(host):
    try:
        raw = scan_ports(host)
        parsed = parse_nmap_ports(raw)
        return host, parsed, raw
    except Exception as e:
        logger.error(f"Port scan failed for {host}: {e}")
        return host, [], ""

def process_header_scan(host):
    try:
        headers = fetch_headers(host)
        return host, headers
    except Exception as e:
        logger.error(f"Header fetch failed for {host}: {e}")
        return host, {}

# -------------------------
# Main (Indentation Fixed)
# -------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Professional Attack Surface Discovery Tool"
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("--no-ports", action="store_true", help="Skip port scanning")
    parser.add_argument("--no-headers", action="store_true", help="Skip header analysis")
    parser.add_argument("-t", "--threads", type=int, default=MAX_THREADS)

    args = parser.parse_args()

    # 1. AUTO UPDATE CHECK (FIXED)
    latest = check_for_update(__version__)
    if latest:
        choice = input(
            f"[!] New version {latest} available. Update now? [Y/n]: "
        ).strip().lower()

        if choice in ("", "y", "yes"):
            apply_update()
            
    # Start Scan Logic
    target = args.domain

    data = {
        "metadata": {
            "target": target,
            "scan_date": datetime.now().isoformat(),
            "version": __version__ # Using __version__ for consistency
        },
        "subdomains": [],
        "alive_hosts": [],
        "ports": {},
        "ports_raw": {},
        "headers": {},
        "misconfigurations": {},
        "risk_scores": {},
        "technologies": {},
        "findings": {},
        "attack_paths": [],
        "mitre_attack": {},
        "kill_chain": {}
    }

    logger.info(f"Scanner started against: {target}")

    # Subdomain Enumeration
    logger.info("Enumerating subdomains...")
    try:
        data["subdomains"] = enumerate_subdomains(target)
        logger.info(f"Found {len(data['subdomains'])} subdomains")
    except Exception as e:
        logger.error(f"Subdomain enumeration failed: {e}")

    # Alive Check
    logger.info("Checking alive hosts...")
    try:
        data["alive_hosts"] = check_alive(data["subdomains"])
        logger.info(f"Alive hosts: {len(data['alive_hosts'])}")
    except Exception as e:
        logger.error(f"Alive check failed: {e}")

    if not data["alive_hosts"]:
        logger.warning("No alive hosts found")
        return

    # Port Scan
    if not args.no_ports:
        logger.info(f"Scanning ports (threads={args.threads})")
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=args.threads
        ) as executor:
            futures = {
                executor.submit(process_port_scan, host): host
                for host in data["alive_hosts"]
            }
            for future in concurrent.futures.as_completed(futures):
                host, parsed, raw = future.result()
                if parsed:
                    data["ports"][host] = parsed
                    data["ports_raw"][host] = raw

    # Headers
    if not args.no_headers:
        logger.info(f"Fetching headers (threads={args.threads})")
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=args.threads
        ) as executor:
            futures = {
                executor.submit(process_header_scan, host): host
                for host in data["alive_hosts"]
            }
            for future in concurrent.futures.as_completed(futures):
                host, headers = future.result()
                data["headers"][host] = headers

    # Analysis Phase
    logger.info("Running analysis engines...")
    for host in data["alive_hosts"]:
        headers = data["headers"].get(host, {})
        
        # Initialize findings for the host
        findings = {}

        if headers:
            # Header Audit and Tech Fingerprint
            issues = scan_headers(headers)
            if issues.get("missing") or issues.get("info_leaks"):
                data["misconfigurations"][host] = issues
            data["technologies"][host] = fingerprint_from_headers(headers)
        
        # Risk Scoring (depends on ports and misconfigurations)
        data["risk_scores"][host] = calculate_risk(
            host,
            ports=data["ports"].get(host, []),
            misconf=data["misconfigurations"].get(host, {})
        )

        # Finding Correlation
        findings = generate_findings(
            host,
            risk=data["risk_scores"].get(host, {}),
            tech=data["technologies"].get(host, []),
            ports=data["ports"].get(host, []),
            misconf=data["misconfigurations"].get(host, {})
        )

        if findings:
            data["findings"][host] = findings

    # Advanced Analysis
    try:
        data["attack_paths"] = build_attack_paths(data)

        # MITRE Mapping
        for entry in map_attack_paths_to_mitre(data["attack_paths"]):
            host = entry.get("host")
            if not host:
                continue
            # Using setdefault is cleaner for aggregation
            data["mitre_attack"].setdefault(host, []).extend(
                entry.get("techniques", [])
            )
            
        # Kill Chain
        data["kill_chain"] = build_kill_chain(data)
        
        # Graph Builder (Silent - creates data for external render)
        build_attack_surface_graph(data)
    except Exception as e:
        logger.error(f"Advanced engine error: {e}")

    # Reporting
    logger.info("Generating reports...")
    os.makedirs("reports/html", exist_ok=True)

    with open("reports/output.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    try:
        export_csv(data, "reports/output.csv")
        export_markdown(data, "reports/output.md")
        export_html(data, "reports/html/report.html")
    except Exception as e:
        logger.error(f"Report generation failed: {e}")

    logger.info("Scan completed successfully")

if __name__ == "__main__":
    main()

