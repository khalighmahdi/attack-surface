# modules/admin_finder.py

import os
import re
from typing import Dict
import requests
from urllib.parse import urljoin, urlparse
from datetime import datetime, timezone

from modules.payload_registry import register_payload   # ✅ FIXED

TIMEOUT = 5

# Well-known server-management panel ports. If we land on one of these,
# it's almost certainly a "primary" admin panel (cPanel, WHM, Plesk, etc.).
PRIMARY_PANEL_PORTS = {2082, 2083, 2086, 2087, 8443, 8880}

# (needle, vendor_name) — used to fingerprint the panel vendor.
PANEL_FINGERPRINTS = [
    ("cpsrvd", "cPanel"),
    ("cPanel", "cPanel"),
    ("WHM", "WHM"),
    ("Plesk", "Plesk"),
    ("DirectAdmin", "DirectAdmin"),
    ("Webmin", "Webmin"),
    ("Synology", "Synology DSM"),
    ("ISPConfig", "ISPConfig"),
    ("Virtualmin", "Virtualmin"),
]

COMMON_ADMIN_PATHS = [
    "admin",
    "administrator",
    "admin/login",
    "panel",
    "cpanel",
    "dashboard",
    "login",
    "manage",
    "secure",
    "wp-admin",
    "wp-login.php",
]

ADMIN_KEYWORDS = [
    "admin",
    "administrator",
    "dashboard",
    "control panel",
    "cpanel",
    "backend",
    "wp-admin",
]

USER_PANEL_KEYWORDS = [
    "account",
    "profile",
    "user",
    "customer",
    "sign in",
    "signup",
]

WORDLIST_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "wordlists",
    "admin.txt",
)

def _classify_panel(url: str, path: str) -> str:
    haystack = f"{url} {path}".lower()
    if any(k in haystack for k in ADMIN_KEYWORDS):
        return "admin"
    if any(k in haystack for k in USER_PANEL_KEYWORDS):
        return "user"
    return "unknown"


def _is_protected(response: requests.Response) -> bool:
    """
    A panel is considered "protected" only if it actively challenges the
    client (HTTP 401/403). A 200 OK that simply renders a login form is
    NOT protected — the form itself is the attack surface.
    """
    return response.status_code in (401, 403)




# ---------------------------------------------------------------------------
# Primary-panel scoring
# ---------------------------------------------------------------------------
# A "primary" admin panel is the panel that actually controls the server
# (cPanel, WHM, Plesk, DirectAdmin, ...), as opposed to a user-facing
# application login form. We score every candidate URL and keep the
# highest-scoring one per host.
#
# The signals are intentionally conservative: false negatives (missing a
# real primary) are far less harmful than false positives (labeling a
# benign login page as a control panel).

def _detect_vendor(response: requests.Response, url: str) -> str:
    """Return the panel vendor name if recognizable, else empty string."""
    haystack = " ".join([
        url,
        response.headers.get("Server", ""),
        response.headers.get("X-Powered-By", ""),
        response.text[:8192] if response.text else "",
    ])
    for needle, vendor in PANEL_FINGERPRINTS:
        if needle.lower() in haystack.lower():
            return vendor
    return ""


def _extract_port(url: str) -> int:
    try:
        return urlparse(url).port or (443 if urlparse(url).scheme == "https" else 80)
    except Exception:
        return 0


def _score_panel(panel: Dict, response: requests.Response = None) -> int:
    """
    Higher = more likely to be the "real" admin panel.

    Signals (rough weights):
      - on a known control-panel port   +10
      - vendor fingerprint matched      +10
      - path hints at a control panel   +6
      - unprotected (no 401/403)        +3
      - redirects to a different host   +5  (often reveals shared hosting)
      - looks like user/app login form  -8
    """
    score = 0
    url = (panel.get("url") or "").lower()
    path = (panel.get("path") or "").lower()

    # 1. Non-standard port is a huge signal (cPanel:2083, Plesk:8443, ...)
    port = _extract_port(panel.get("url", ""))
    if port in PRIMARY_PANEL_PORTS:
        score += 10

    # 2. Vendor fingerprint (Server header, body, ...)
    if response is not None:
        vendor = _detect_vendor(response, panel.get("url", ""))
        if vendor:
            panel["vendor"] = vendor
            score += 10

    # 3. Path hints
    if any(k in path for k in ("cpanel", ":2082", ":2083", ":2086", ":2087", "whm", "plesk", "directadmin", "webmin")):
        score += 6

    # 4. Unprotected = more interesting (no auth challenge at the edge)
    if not panel.get("protected"):
        score += 3

    # 5. Cross-host redirect (e.g. *.hostdl.com) — exposes shared infra
    initial_domain = panel.get("_initial_domain", "")
    final_host = urlparse(panel.get("url", "")).hostname or ""
    if initial_domain and final_host and initial_domain.lower() not in final_host.lower():
        score += 5
        panel["cross_host_redirect"] = True

    # 6. Path-based demotion for obviously user-facing routes
    if any(k in path for k in ("login-register", "signin", "signup", "customer", "my-account", "user/login")):
        score -= 8

    # 7. Generic "login" path with form-based auth is rarely the primary
    if path in ("/login", "/signin", "/user/login") and not port in PRIMARY_PANEL_PORTS:
        score -= 4

    return score


def find_admin_panels(alive_hosts, emit=None):
    """
    Returns:
        {
          "<domain>": [
              {"path", "url", "status_code", "protected",
               "panel_type", "score" (int), "vendor" (str|""),
               "is_primary" (bool), "cross_host_redirect" (bool)},
              ...
          ],
          ...
        }
    """
    results = {}

    for host in alive_hosts or []:
        domain = host.get("domain") if isinstance(host, dict) else host
        protocol = host.get("protocol", "https") if isinstance(host, dict) else "https"

        if not domain:
            continue

        base_url = f"{protocol}://{domain}/"
        findings = []

        for path in COMMON_ADMIN_PATHS:
            url = urljoin(base_url, path)

            try:
                r = requests.get(
                    url,
                    timeout=TIMEOUT,
                    allow_redirects=True,
                    headers={"User-Agent": "AttackSurfaceScanner"},
                )

                panel_type = _classify_panel(r.url, path)
                protected = _is_protected(r)

                if r.status_code in (200, 301, 302, 401, 403):
                    finding = {
                        "path": f"/{path}",
                        "url": r.url,
                        "status_code": r.status_code,
                        "protected": protected,
                        "panel_type": panel_type,
                        "_initial_domain": domain,  # used by _score_panel
                    }
                    # Compute the priority score and persist it
                    finding["score"] = _score_panel(finding, r)
                    finding["vendor"] = finding.get("vendor", "")
                    finding["is_primary"] = False  # set below
                    finding["cross_host_redirect"] = bool(finding.get("cross_host_redirect", False))
                    findings.append(finding)

                    if emit:
                        event_type = "admin_panel"
                        if panel_type == "admin" and r.status_code == 200 and not protected:
                            event_type = "ADMIN_PANEL_EXPOSED"

                        emit({
                            "type": event_type,
                            "domain": domain,
                            **finding,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        })

                    if panel_type == "admin" and r.status_code == 200 and not protected:
                        register_payload({
                            "id": f"ffuf_admin_{domain}",
                            "title": f"Bruteforce admin panel on {domain}",
                            "description": f"FFUF against exposed admin panel {r.url}",
                            "command": (
                                f"ffuf -u '{r.url.rstrip('/')}/FUZZ' "
                                f"-w '{WORDLIST_PATH}' "
                                f"-mc 200,301,302,401,403 "
                                f"-t 40 -timeout 10 "
                                f"-of json "
                                f"-o 'ffuf_{domain.replace('.', '_')}_admin.json'"
                            ),
                            "requires_expert": True,
                        })

            except Exception:
                continue

        if findings:
            # Mark the highest-scoring panel as the primary for this host.
            # A primary must have a strictly positive score; otherwise the
            # "best" panel isn't really a control panel (e.g. all redirects
            # to a user login form).
            best = max(findings, key=lambda f: f.get("score", -100))
            if best.get("score", 0) > 0:
                best["is_primary"] = True
                best_id = best["url"]
                if emit:
                    emit({
                        "type": "PRIMARY_ADMIN_PANEL",
                        "domain": domain,
                        "url": best["url"],
                        "path": best["path"],
                        "port": _extract_port(best["url"]),
                        "vendor": best.get("vendor", ""),
                        "score": best["score"],
                        "protected": best["protected"],
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
            results[domain] = findings

    return results

