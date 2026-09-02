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

# -------------------------
# Batch Nmap Scan (fast)
# -------------------------
def _run_nmap_batch(targets: list) -> dict:
    """
    Scan many IPs in ONE nmap invocation using -iL.
    targets: [(domain, ip), ...] with ip != None
    Returns {domain: {ip, open_ports:[...]}} (+ per-host 'error' keys kept)
    """
    import tempfile, os
    results = {}
    ips = {}
    for domain, ip in targets:
        results[domain] = {"ip": ip, "open_ports": []}
        if ip:
            ips.setdefault(ip, []).append(domain)

    if not ips:
        return results

    common_ports = "21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,8080,8443"

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
        for ip in ips:
            tf.write(ip + "\n")
        list_path = tf.name

    command = [
        "nmap", "-Pn", "-sT", "-T4",
        f"-p{common_ports}",
        "-iL", list_path,
        "-oG", "-",
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                check=True, timeout=300)
        # grepable format: "Host: 1.2.3.4 ()\tPorts: 80/open/tcp//http///..."
        for line in result.stdout.splitlines():
            if not line or line.startswith("#") or "Ports:" not in line:
                continue
            host_part, _, ports_part = line.partition("Ports:")
            ip = host_part.split("Host:", 1)[-1].split("(")[0].strip()
            open_ports = []
            for entry in ports_part.split(", "):
                if "/open/" not in entry:
                    continue
                parts = entry.split("/")
                try:
                    port_num = int(parts[0])
                    service = parts[4] if len(parts) > 4 else "unknown"
                except Exception:
                    continue
                open_ports.append({"port": port_num, "service": service, "protocol": "tcp"})
            for domain in ips.get(ip, []):
                results[domain]["open_ports"] = open_ports
    except FileNotFoundError:
        for domain in results:
            results[domain]["error"] = "Nmap not installed"
    except subprocess.TimeoutExpired:
        for domain in results:
            if not results[domain].get("open_ports"):
                results[domain]["error"] = "Nmap scan timed out"
    except subprocess.CalledProcessError as e:
        err = (e.stderr or "nmap failed").strip()[:120]
        for domain in results:
            results[domain]["error"] = err
    finally:
        try:
            os.unlink(list_path)
        except OSError:
            pass
    return results

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

    port_scan_results = _run_nmap_batch(
        [(h.get("domain"), h.get("ip")) for h in alive_hosts]
    )

    for domain, result in port_scan_results.items():
        if result.get("error"):
            logging.warning("Port scan %s: %s", domain, result["error"])
        if ndjson_emit:
            ndjson_emit({
                "type": "port_scan",
                "domain": domain,
                "ip": result.get("ip"),
                "open_ports": result.get("open_ports", []),
                "error": result.get("error"),
            })

    logging.info("Port scanning completed (batch mode)")
    return port_scan_results

