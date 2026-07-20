# modules/alive.py

import logging
import requests
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")


def check_single_host(subdomain: str) -> dict | None:
    """
    Checks if a single subdomain is alive via HTTP/HTTPS and DNS resolution.
    """
    try:
        ip = socket.gethostbyname(subdomain)

        # Try HTTPS first
        try:
            requests.head(
                f"https://{subdomain}",
                timeout=5,
                allow_redirects=True
            )
            logging.debug("%s is alive (HTTPS)", subdomain)
            return {
                "domain": subdomain,
                "ip": ip,
                "status": "alive",
                "protocol": "https",
            }
        except requests.exceptions.RequestException:
            pass  # HTTPS failed, try HTTP

        # Try HTTP
        try:
            requests.head(
                f"http://{subdomain}",
                timeout=5,
                allow_redirects=True
            )
            logging.debug("%s is alive (HTTP)", subdomain)
            return {
                "domain": subdomain,
                "ip": ip,
                "status": "alive",
                "protocol": "http",
            }
        except requests.exceptions.RequestException:
            pass  # HTTP failed

        logging.debug(
            "%s DNS resolved but not reachable via HTTP/HTTPS",
            subdomain
        )
        return {
            "domain": subdomain,
            "ip": ip,
            "status": "dns_resolved_no_http",
        }

    except socket.gaierror:
        logging.debug("%s has no DNS record", subdomain)
        return {
            "domain": subdomain,
            "ip": None,
            "status": "not_resolved",
        }

    except Exception as e:
        logging.warning("Error checking %s: %s", subdomain, e)
        return {
            "domain": subdomain,
            "ip": None,
            "status": "error",
            "message": str(e),
        }


def check_alive(subdomains: list) -> list:
    """
    Checks if given subdomains are alive (reachable via HTTP/HTTPS).
    Original function — preserved.
    """
    alive_hosts = []

    if not subdomains:
        logging.info("No subdomains to check for aliveness.")
        return []

    logging.info(
        "Checking aliveness for %d subdomains...",
        len(subdomains)
    )

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(check_single_host, s): s
            for s in subdomains
        }

        for future in as_completed(futures):
            result = future.result()
            if result and result.get("status") == "alive":
                alive_hosts.append(result)
            elif result:
                logging.debug(
                    "Host %s status: %s",
                    result.get("domain"),
                    result.get("status"),
                )

    logging.info("%d hosts found alive.", len(alive_hosts))
    return alive_hosts


# ✅ Adapter for attack_surface.py (NEW, SAFE)
def check_alive_hosts(domain: str) -> list:
    """
    Engine adapter.
    attack_surface.py expects this signature.
    """
    # For now, operate on root domain only.
    return check_alive([domain])


# Local test
if __name__ == "__main__":
    test_subdomains = [
        "google.com",
        "nonexistent.example.com",
        "github.com",
        "docs.python.org",
    ]
    results = check_alive(test_subdomains)
    import json
    print(json.dumps(results, indent=2))

