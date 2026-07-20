# modules/ports.py

import logging
import subprocess
import json

try:
    from core.stream import ndjson_emit
except Exception:
    ndjson_emit = None

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s - %(message)s"
)


# -------------------------
# Internal: Nmap Scan
# -------------------------
def _run_nmap_scan(ip_address: str) -> dict:
    """
    Runs a basic Nmap scan on common ports using TCP connect scan (-sT)
    This is unprivileged and works on Termux.
    """

    common_ports = (
        "21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,8080,8443"
    )

    command = [
        "nmap",
        "-Pn",
        "-sT",
        "-T4",
        f"-p{common_ports}",
        ip_address,
        "-oG",
        "-"
    ]

    logging.debug("Running Nmap command: %s", " ".join(command))

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=60
        )

        open_ports = []

        for line in result.stdout.splitlines():
            if not line or line.startswith("#"):
                continue

            if "Ports:" not in line:
                continue

            _, ports_part = line.split("Ports:", 1)
            entries = ports_part.split(", ")

            for entry in entries:
                # example: 80/open/tcp//http///
                if "/open/" not in entry:
                    continue

                parts = entry.split("/")
                try:
                    port_num = int(parts[0])
                    service = parts[4] if len(parts) > 4 else "unknown"
                except Exception:
                    continue

                open_ports.append({
                    "port": port_num,
                    "service": service,
                    "protocol": "tcp"
                })

        return {
            "ip": ip_address,
            "open_ports": open_ports
        }

    except subprocess.TimeoutExpired:
        logging.warning("Nmap scan timed out for %s", ip_address)
        return {
            "ip": ip_address,
            "error": "Nmap scan timed out"
        }

    except FileNotFoundError:
        logging.error("Nmap not found on system")
        return {
            "ip": ip_address,
            "error": "Nmap not installed"
        }

    except subprocess.CalledProcessError as e:
        logging.error("Nmap scan failed for %s: %s", ip_address, e.stderr)
        return {
            "ip": ip_address,
            "error": e.stderr.strip()
        }

    except Exception as e:
        logging.error("Unexpected error scanning %s: %s", ip_address, e)
        return {
            "ip": ip_address,
            "error": str(e)
        }


# -------------------------
# Public API
# -------------------------
def scan_ports(alive_hosts: list) -> dict:
    """
    Performs port scanning for alive hosts.
    Returns:
        {
            domain: {
                ip,
                open_ports: []
            }
        }
    """

    if not alive_hosts:
        logging.info("No alive hosts to scan ports")
        return {}

    port_scan_results = {}
    logging.info("Starting port scanning for %d hosts...", len(alive_hosts))

    for host_info in alive_hosts:
        domain = host_info.get("domain")
        ip = host_info.get("ip")

        if not ip:
            logging.warning("Skipping %s: no IP address", domain)
            port_scan_results[domain] = {
                "error": "No IP address available"
            }

            if ndjson_emit:
                ndjson_emit({
                    "type": "port_scan",
                    "domain": domain,
                    "error": "No IP address"
                })

            continue

        logging.debug("Scanning ports for %s (%s)", domain, ip)
        result = _run_nmap_scan(ip)
        port_scan_results[domain] = result

        # -------------------------
        # NDJSON event
        # -------------------------
        if ndjson_emit:
            ndjson_emit({
                "type": "port_scan",
                "domain": domain,
                "ip": ip,
                "open_ports": result.get("open_ports", []),
                "error": result.get("error")
            })

    logging.info("Port scanning completed")
    return port_scan_results

