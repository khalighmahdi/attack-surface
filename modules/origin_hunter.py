"""origin_hunter.py — find the real origin IP behind a CDN/WAF.

When a domain is fronted by Cloudflare/Arvan/etc, the DNS IP is a CDN
edge — not the real server. This module hunts for the true origin via:

  1. Historical DNS (crt.sh, DNSDumpster-style passive sources)
  2. Mail records (MX → often points to origin or a mail server on same IP)
  3. Direct IP access (Host-header bypass)
  4. SSL certificate SANs (certs often issued to origin IP)
  5. Subdomain IP correlation (non-CDN subdomains → same hosting)

Output: list of candidate origin IPs with confidence score + evidence.
"""
from __future__ import annotations

import logging
import re
import socket
import ssl
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("AttackSurface.OriginHunter")

# passive sources for historical DNS
HISTORICAL_SOURCES = [
    ("crt.sh", "https://crt.sh/?q=%25.{domain}&output=json"),
]


def _resolve(host: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        return sorted({info[4][0] for info in infos})
    except Exception:
        return []


def _is_cdn_ip(ip: str) -> Optional[str]:
    from modules.cdn_detector import detect_cdn
    return detect_cdn(ip)


def dns_history(domain: str) -> List[Dict[str, Any]]:
    """Query crt.sh for historical certificates → subdomain IPs."""
    import json as _json
    import urllib.request
    import ssl as _ssl
    results = []
    try:
        ctx = _ssl.create_default_context()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "attack-surface"})
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            data = _json.loads(resp.read().decode())
        names = set()
        for entry in data[:500]:
            name_value = entry.get("name_value", "")
            for line in name_value.split("\n"):
                line = line.strip().lower()
                if line.endswith(domain) and "*" not in line:
                    names.add(line)
        for name in sorted(names)[:50]:
            ips = _resolve(name)
            for ip in ips:
                cdn = _is_cdn_ip(ip)
                results.append({
                    "subdomain": name, "ip": ip,
                    "cdn": cdn or "",
                    "source": "crt.sh",
                })
    except Exception as e:
        logger.debug("crt.sh query failed: %s", e)
    return results


def mail_records(domain: str) -> List[Dict[str, Any]]:
    """MX records → mail server IPs (often same hosting as origin)."""
    import subprocess
    results = []
    try:
        r = subprocess.run(["dig", "+short", "MX", domain],
                           capture_output=True, text=True, timeout=10)
        for line in (r.stdout or "").strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                mx_host = parts[1].rstrip(".")
                ips = _resolve(mx_host)
                for ip in ips:
                    cdn = _is_cdn_ip(ip)
                    results.append({
                        "mx": mx_host, "ip": ip,
                        "cdn": cdn or "",
                        "source": "MX record",
                    })
    except Exception as e:
        logger.debug("MX lookup failed: %s", e)
    return results


def direct_ip_access(domain: str, candidate_ips: List[str]) -> List[Dict[str, Any]]:
    """Try accessing each candidate IP with Host: header set to domain.
    If the response looks like the real site → high confidence origin."""
    import urllib.request
    import ssl as _ssl
    results = []
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for ip in candidate_ips[:10]:
        for scheme in ("https", "http"):
            try:
                url = f"{scheme}://{ip}/"
                req = urllib.request.Request(url, headers={
                    "Host": domain,
                    "User-Agent": "attack-surface-origin-probe",
                })
                with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                    body = resp.read(2048).decode(errors="ignore").lower()
                    status = resp.status
                    # check if response mentions the domain (real site)
                    mentions_domain = domain.lower() in body
                    server = resp.headers.get("Server", "")
                    results.append({
                        "ip": ip, "scheme": scheme, "status": status,
                        "mentions_domain": mentions_domain,
                        "server": server,
                        "confidence": 90 if mentions_domain else 40,
                        "evidence": f"HTTP {status} with Host: {domain}",
                    })
                    break  # https worked, skip http
            except Exception:
                continue
    return results


def correlate_subdomain_ips(domain: str, subdomain_ips: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    """Find IPs shared by multiple non-CDN subdomains (likely origin)."""
    from collections import Counter
    ip_count: Counter = Counter()
    ip_hosts: Dict[str, List[str]] = {}

    for sub, ips in subdomain_ips.items():
        for ip in ips:
            if not _is_cdn_ip(ip):
                ip_count[ip] += 1
                ip_hosts.setdefault(ip, []).append(sub)

    # IPs hosting 2+ non-CDN subdomains are strong origin candidates
    candidates = []
    for ip, count in ip_count.most_common(10):
        if count >= 2:
            candidates.append({
                "ip": ip, "subdomains": ip_hosts[ip][:5],
                "confidence": min(95, 50 + count * 15),
                "evidence": f"shared by {count} non-CDN subdomains",
            })
    return candidates


def hunt_origin(domain: str, subdomain_ips: Optional[Dict[str, List[str]]] = None
                ) -> Dict[str, Any]:
    """Full origin hunt. Returns {candidates: [...], method: str}."""
    all_candidates: List[Dict[str, Any]] = []

    # 1. Historical DNS
    hist = dns_history(domain)
    for h in hist:
        if not h["cdn"]:  # non-CDN IP from history
            all_candidates.append({
                "ip": h["ip"], "confidence": 70,
                "evidence": f"historical DNS: {h['subdomain']}",
            })

    # 2. MX records
    mx = mail_records(domain)
    for m in mx:
        if not m["cdn"]:
            all_candidates.append({
                "ip": m["ip"], "confidence": 60,
                "evidence": f"MX: {m['mx']}",
            })

    # 3. Subdomain correlation
    if subdomain_ips:
        corr = correlate_subdomain_ips(domain, subdomain_ips)
        all_candidates.extend(corr)

    # deduplicate by IP, keep highest confidence
    best: Dict[str, Dict[str, Any]] = {}
    for c in all_candidates:
        ip = c["ip"]
        if ip not in best or c["confidence"] > best[ip]["confidence"]:
            best[ip] = c

    candidates = sorted(best.values(), key=lambda x: -x["confidence"])[:10]

    # 4. Direct IP access validation (only if we have candidates)
    if candidates:
        validated = direct_ip_access(domain, [c["ip"] for c in candidates])
        for v in validated:
            for c in candidates:
                if c["ip"] == v["ip"]:
                    c["confidence"] = max(c["confidence"], v["confidence"])
                    c["validated"] = v.get("mentions_domain", False)
                    c["http_status"] = v.get("status")

    return {
        "domain": domain,
        "candidates": candidates,
        "methods_used": ["crt.sh DNS history", "MX records",
                         "subdomain IP correlation", "direct IP access"],
    }
