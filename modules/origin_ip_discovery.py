import socket
from typing import List, Dict

# --- Known CDN IP Prefixes (partial, enough for heuristic)
CDN_IP_RANGES = [
    "104.",        # Cloudflare
    "185.143.",    # ArvanCloud
    "162.159.",    # Cloudflare
]

def is_cdn_ip(ip: str) -> bool:
    """
    Checks whether IP likely belongs to a CDN
    """
    return any(ip.startswith(prefix) for prefix in CDN_IP_RANGES)

def resolve_ip(host: str) -> str | None:
    """
    Resolves hostname to IP
    """
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def subdomain_ip_correlation(alive_hosts: List[Dict]) -> List[Dict]:
    """
    Detect origin IP via subdomain correlation.
    alive_hosts example item:
    {
        "host": "mail.example.com",
        "ip": "185.x.x.x",
        "protocol": "https"
    }
    """
    events = []

    for host in alive_hosts:
        ip = host.get("ip")
        hostname = host.get("host")

        if not ip or not hostname:
            continue

        # Skip CDN IPs
        if is_cdn_ip(ip):
            continue

        # Found a likely origin IP
        events.append({
            "type": "origin_ip",
            "ip": ip,
            "source": "subdomain_correlation",
            "confidence": "high",
            "related_host": hostname,
            "severity": "critical"
        })

    return events
