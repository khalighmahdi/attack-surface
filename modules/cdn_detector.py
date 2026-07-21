"""
modules/cdn_detector.py
========================
Detect whether an IP belongs to a known CDN / WAF / cloud provider.

Why this matters
----------------
If the target is fronted by Cloudflare/Arvan/Fastly, the public IP
that DNS returns is NOT the real server — it's a CDN edge node.
Port-scanning it is:
  1. Useless (you'll never reach the origin)
  2. Dangerous (Cloudflare rate-limits and bans aggressive scanners)
  3. Potentially illegal (scanning infrastructure you don't own)

The runner uses `detect_cdn` to skip port-scans on CDN-fronted hosts
and to record this fact as a finding so the user knows to look
elsewhere (subdomain takeover, origin IP leak via mail, etc.).

Note: Range-based detection is best-effort. A CDN may use a fresh IP
out of its announced range. For higher confidence, combine with an
HTTP header check (`Server: cloudflare`, `cf-ray`, ...).
"""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional, Tuple

# Public IP ranges (CIDR) for the most common CDNs / WAFs / clouds.
# Keep this list focused on providers that actively front web traffic;
# generic clouds (AWS, GCP, Azure) are listed under "Cloud" because
# scanning an EC2 IP is not the same as scanning Cloudflare.
#
# Sources: each provider's published IP list, sampled 2026.
CDN_RANGES: Dict[str, List[str]] = {
    "Cloudflare": [
        "104.16.0.0/12",
        "172.64.0.0/13",
        "188.114.96.0/20",
        "190.93.240.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "131.0.72.0/22",
    ],
    "ArvanCloud": [
        "185.143.0.0/16",
        "45.82.0.0/16",
        "45.159.0.0/16",
    ],
    "Fastly": [
        "151.101.0.0/16",
        "199.232.0.0/16",
        "23.235.32.0/20",
    ],
    "Akamai": [
        "23.32.0.0/11",
        "23.192.0.0/11",
        "104.64.0.0/10",
        "184.24.0.0/13",
    ],
    "CloudFront": [
        "13.32.0.0/15",
        "13.224.0.0/14",
        "52.84.0.0/15",
        "54.182.0.0/16",
        "54.192.0.0/16",
        "99.84.0.0/16",
        "143.204.0.0/16",
    ],
    "Incapsula": [
        "199.83.128.0/21",
        "198.143.32.0/19",
        "45.60.0.0/16",
        "45.223.0.0/16",
    ],
    "Sucuri": [
        "192.88.134.0/23",
        "185.93.228.0/22",
        "192.124.249.0/24",
    ],
    "StackPath": [
        "151.139.0.0/16",
    ],
    "KeyCDN": [
        "5.172.0.0/19",
    ],
    "BunnyCDN": [
        "91.220.0.0/16",
    ],
    "GCore": [
        "92.223.0.0/16",
        "194.36.144.0/22",
    ],
    "BypassWAF (generic)": [
        # Some lesser-known WAFs share these ranges; treat as CDN
        "194.5.249.0/22",
    ],
}


def _build_index():
    """Pre-resolve all CIDRs to (network, vendor) tuples for fast lookup."""
    index: List[Tuple[ipaddress.IPv4Network, str]] = []
    for vendor, cidrs in CDN_RANGES.items():
        for cidr in cidrs:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                index.append((net, vendor))
            except ValueError:
                # Skip malformed entries rather than crash the scanner
                continue
    return index


_INDEX = _build_index()


def detect_cdn(ip: str) -> Optional[str]:
    """
    Return the CDN/WAF vendor if `ip` is in a known range, else None.
    """
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    # Only IPv4 ranges listed above; IPv6 is rare for these providers today
    if isinstance(addr, ipaddress.IPv6Address):
        return None
    for net, vendor in _INDEX:
        if addr in net:
            return vendor
    return None


def detect_cdn_or_cloud(ip: str) -> Optional[str]:
    """
    Like detect_cdn, but also flags known generic cloud providers
    (AWS, GCP, Azure) where a port scan is also pointless for the same
    reason — the IP is one of millions of multi-tenant addresses.
    """
    cdn = detect_cdn(ip)
    if cdn:
        return cdn
    # Generic clouds (best-effort prefix match; not exhaustive)
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv4Address):
        oct1 = int(str(addr).split(".")[0])
        if oct1 == 3:  # AWS US-east partial; not exhaustive
            return "AWS (likely)"
        if oct1 in (13, 52, 54):  # AWS
            return "AWS (likely)"
        if oct1 in (34, 35):  # GCP
            return "GCP (likely)"
        if oct1 in (13, 20, 40, 52, 104):  # Azure (rough)
            return "Azure (likely)"
    return None


# ---------------------------------------------------------------------------
# Header-based detection (more reliable, used as a follow-up)
# ---------------------------------------------------------------------------

CDN_HEADER_SIGNATURES = {
    "Cloudflare":      ["cf-ray", "cf-cache-status", "server: cloudflare"],
    "CloudFront":      ["x-amz-cf-id", "via: cloudfront", "x-amz-cf-pop"],
    "Fastly":          ["x-served-by", "x-fastly", "fastly-"],
    "Akamai":          ["x-akamai", "akamai-", "x-akamai-request-id"],
    "ArvanCloud":      ["ar-poweredby", "server: arvancloud"],
    "Incapsula":       ["x-iinfo", "incap_ses_", "visid_incap_"],
    "Sucuri":          ["x-sucuri-id", "x-sucuri-cache"],
    "BunnyCDN":        ["bunnycdn", "server: bunnycdn"],
    "GCore":           ["gcw-cache", "server: gcore"],
    "Vercel":          ["x-vercel-id"],
    "Netlify":         ["x-nf-request-id", "server: netlify"],
    "Heroku":          ["via: 1.1 vegur"],
    "GitHub Pages":    ["server: github.com"],
}


def detect_cdn_from_headers(headers: Dict[str, str]) -> Optional[str]:
    """
    Look at HTTP response headers for CDN-specific markers. This is
    more reliable than IP range matching because providers can change
    their IP allocations without notice.
    """
    if not headers:
        return None
    lower = {k.lower(): (v or "").lower() for k, v in headers.items()}
    for vendor, sigs in CDN_HEADER_SIGNATURES.items():
        for sig in sigs:
            if ":" in sig:
                k, v = sig.split(":", 1)
                if k.strip() in lower and v.strip() in lower[k]:
                    return vendor
            else:
                # Bare substring
                for hv in lower.values():
                    if sig in hv:
                        return vendor
                    if sig in str(lower):
                        return vendor
    return None
