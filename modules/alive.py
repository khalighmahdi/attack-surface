# modules/alive.py

import logging
import requests
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

# Realistic browser UA — many WAFs (esp. Iranian CDNs) block scanner UAs with 403
HEADERS = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
}


def _curl_alive(subdomain: str, ip: str = "") -> dict | None:
    """Curl-based aliveness check — bypasses WAF TLS fingerprint detection.

    BitNinja/Cloudflare reset Python requests TLS fingerprints but allow
    curl/browser-like connections. Uses full browser headers + HTTP/2.
    """
    import subprocess
    for proto in ("https", "http"):
        url = f"{proto}://{subdomain}"
        try:
            r = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 "
                        "Safari/537.36",
                 "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                 "-H", "Accept-Language: en-US,en;q=0.9",
                 "-H", "Sec-Fetch-Dest: document",
                 "-H", "Sec-Fetch-Mode: navigate",
                 "-H", "sec-ch-ua: \"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\"",
                 "-H", "sec-ch-ua-mobile: ?0",
                 "-H", "sec-ch-ua-platform: \"Windows\"",
                 "--http2", "-L", "--max-time", "12", url],
                capture_output=True, text=True, timeout=15,
            )
            status = int(r.stdout.strip()) if r.stdout.strip().isdigit() else 0
            if 200 <= status < 500:
                logging.debug("%s is alive via curl (%s, HTTP %d)",
                              subdomain, proto, status)
                return {"domain": subdomain, "ip": ip, "status": "alive",
                        "protocol": proto, "http_status": status,
                        "method": "curl"}
        except Exception:
            continue
    return None


def check_single_host(subdomain: str) -> dict | None:
    """Check if a single subdomain is reachable via HTTP/HTTPS.

    Order matters: curl goes FIRST because it carries a browser TLS
    fingerprint — several WAFs (BitNinja, Iranian CDNs) reset Python's
    TLS handshake while accepting curl, and the old requests-first order
    cost ~90s per blocked host before falling back.

    A host that resolves in DNS but never answers HTTP is still returned
    (status ``dns_resolved_no_http``): it has a routable IP, so the port
    scanner and Knull can still work with it. Only hosts with no DNS
    record are dropped.
    """
    try:
        ip = socket.gethostbyname(subdomain)
    except socket.gaierror:
        logging.debug("%s has no DNS record", subdomain)
        return {"domain": subdomain, "ip": None, "status": "not_resolved"}
    except Exception as e:
        logging.warning("Error resolving %s: %s", subdomain, e)
        return {"domain": subdomain, "ip": None, "status": "error",
                "message": str(e)}

    # 1) curl first — fastest path for WAF-fronted hosts.
    curl_result = _curl_alive(subdomain, ip)
    if curl_result:
        return curl_result

    # 2) requests fallback — catches servers that answer Python but not curl.
    #    HEAD only: curl above already exercises GET.
    try:
        s = requests.Session()
        s.headers.update(HEADERS)
        for proto in ("https", "http"):
            url = f"{proto}://{subdomain}"
            try:
                s.head(url, timeout=(4, 8), allow_redirects=True)
                logging.debug("%s is alive (%s HEAD)", subdomain, proto)
                return {"domain": subdomain, "ip": ip, "status": "alive",
                        "protocol": proto}
            except requests.exceptions.RequestException:
                continue
    except Exception as e:
        logging.warning("Error checking %s: %s", subdomain, e)

    logging.debug("%s DNS resolved but not reachable via HTTP/HTTPS", subdomain)
    return {"domain": subdomain, "ip": ip, "status": "dns_resolved_no_http"}


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
            if not result:
                continue
            status = result.get("status")
            if status == "alive":
                alive_hosts.append(result)
            elif status == "dns_resolved_no_http":
                # Reachable at the IP layer even though HTTP never answered.
                # Keep it: port scanning and Knull work on IPs, and dropping
                # these is what left recent scans with zero attack surface.
                result["http_ok"] = False
                alive_hosts.append(result)
            else:
                logging.debug(
                    "Host %s status: %s",
                    result.get("domain"),
                    status,
                )

    logging.info("%d host(s) kept (alive + DNS-resolved).", len(alive_hosts))
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

