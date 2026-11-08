import requests
import socket
from modules.cdn_detector import detect_cdn

CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
TIMEOUT = 8


def get_historical_subdomains(domain: str):
    """
    Fetch historical subdomains from crt.sh
    """
    subdomains = set()
    try:
        url = CRT_SH_URL.format(domain=domain)
        resp = requests.get(url, timeout=TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                if sub.endswith(domain):
                    subdomains.add(sub)

        return sorted(subdomains), None

    except Exception as e:
        return [], str(e)


def resolve_ip(host: str):
    """
    Resolve IPv4 addresses for a hostname
    """
    ips = set()
    try:
        results = socket.getaddrinfo(host, None)
        for r in results:
            ip = r[4][0]
            if ":" not in ip:  # IPv4 only
                ips.add(ip)
    except Exception:
        pass

    return list(ips)


def discover_historical_dns(domain: str) -> list:
    """
    Core historical DNS discovery logic
    Returns a flat list used by the main pipeline
    """
    findings = []

    subdomains, error = get_historical_subdomains(domain)
    if error:
        return []

    for sub in subdomains:
        ips = resolve_ip(sub)
        for ip in ips:
            cdn = detect_cdn(ip)
            findings.append({
                "subdomain": sub,
                "ip": ip,
                "cdn": cdn,
                "origin_candidate": cdn is None
            })

    return findings


def discover_historical_origins(domain: str) -> list:
    """
    ✅ Public API used by attack_surface.py
    Wrapper for backward compatibility
    """
    return discover_historical_dns(domain)

