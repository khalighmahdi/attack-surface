"""
modules/takeover_check.py
==========================
Blue-Team: subdomain takeover detection.

A dangling DNS record (CNAME to a deprovisioned cloud service) lets an
attacker serve THEIR content on YOUR subdomain — cookie theft, phishing
on your brand, CSP bypass. This module:

  1. Finds alive hosts whose HTTP answer carries a takeover fingerprint
     (e.g. "There isn't a GitHub Pages site here.")
  2. Flags GONE_HOSTS from baseline diffs whose CNAME still points at
     a known service (handled via runner integration).

Fingerprint list covers the common platforms (GitHub Pages, S3, Azure,
Heroku, Shopify, Fastly, Zendesk, Surge, Bitbucket, ...).
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List

import requests

try:
    from core.stream import ndjson_emit
except Exception:
    ndjson_emit = None

logger = logging.getLogger("AttackSurface.Takeover")

TIMEOUT = 6

# body fingerprint -> service
FINGERPRINTS: List[tuple] = [
    (r"There isn\'?t a GitHub Pages site here", "GitHub Pages"),
    (r"The specified bucket does not exist", "AWS S3"),
    (r"<error><code>NotFound</code>", "AWS S3 (XML)"),
    (r"404 Not Found.*nginx.*azurewebsites", "Azure Web Apps"),
    (r"404 Web Site not found", "Azure Web Apps"),
    (r"No such app", "Heroku"),
    (r"Sorry, this shop is currently unavailable", "Shopify"),
    (r"Fastly error: unknown domain", "Fastly"),
    (r"Help Center Closed", "Zendesk"),
    (r"project not found", "Surge.sh"),
    (r"Repository not found", "Bitbucket"),
    (r"The site you were looking for couldn\'?t be found", "Tumblr"),
    (r"Domain not found", "Contentful"),
    (r"campaign not found", "Campaingmonitor"),
    (r".datawig", "Webflow"),
]


def check_takeover(alive_hosts: list, rate_limiter=None) -> List[Dict[str, Any]]:
    """
    Returns a list of findings:
      [{host, service, evidence_url, severity: "critical"}, ...]
    """
    findings: List[Dict[str, Any]] = []

    for host in alive_hosts or []:
        domain = host.get("domain") if isinstance(host, dict) else host
        protocol = host.get("protocol", "https") if isinstance(host, dict) else "https"
        if not domain:
            continue
        url = f"{protocol}://{domain}/"
        try:
            if rate_limiter is not None:
                rate_limiter.wait()
            else:
                try:
                    from core.rate_limiter import get_limiter
                    get_limiter().wait()
                except Exception:
                    pass
            r = requests.get(url, timeout=TIMEOUT, allow_redirects=True,
                             headers={"User-Agent": "AttackSurfaceScanner"})
            body = r.text or ""
            for pattern, service in FINGERPRINTS:
                if re.search(pattern, body, re.I):
                    findings.append({
                        "host": domain,
                        "service": service,
                        "evidence_url": r.url,
                        "matched": pattern[:60],
                        "severity": "critical",
                    })
                    if ndjson_emit:
                        ndjson_emit({
                            "type": "SUBDOMAIN_TAKEOVER",
                            "domain": domain,
                            "service": service,
                            "severity": "critical",
                        })
                    logger.warning("CRITICAL: possible %s takeover at %s",
                                   service, domain)
                    break
        except requests.exceptions.RequestException:
            continue
        except Exception as e:
            logger.debug("takeover check error %s: %s", domain, e)

    return findings
