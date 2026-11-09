"""
modules/setup_page_detector.py
===============================
Detects exposed CMS install/setup pages (WordPress setup-config.php,
wp-admin install, phpMyAdmin setup, Laravel installer, ...).

An exposed setup page means the CMS is HALF-INSTALLED and anyone can
complete it (point it at their own DB or hijack the site). This is a
CRITICAL finding.
"""
from __future__ import annotations

import logging
from typing import Dict, List

import requests

try:
    from core.stream import ndjson_emit
except Exception:
    ndjson_emit = None

logger = logging.getLogger("AttackSurface.SetupPages")

TIMEOUT = 6

# (path, needle-in-body, cms-name)
SETUP_PAGES = [
    ("/wp-admin/setup-config.php", "setup-config", "WordPress (uninstalled)"),
    ("/wp-admin/install.php", "wp-admin/install", "WordPress (install)"),
    ("/install.php", "install", "Generic PHP installer"),
    ("/install/index.php", "install", "Generic installer (/install)"),
    ("/installer.php", "installer", "Duplicator/Installer"),
    ("/laravel/install", "laravel", "Laravel installer"),
    ("/phpmyadmin/setup/index.php", "setup", "phpMyAdmin setup"),
    ("/setup/index.php", "setup", "Generic setup wizard"),
]


def _audit_host_setup(host, rate_limiter=None) -> tuple[str, List[dict]]:
    domain = host.get("domain") if isinstance(host, dict) else host
    protocol = host.get("protocol", "https") if isinstance(host, dict) else "https"
    out: List[dict] = []
    if not domain:
        return domain, out

    for path, needle, cms in SETUP_PAGES:
        url = f"{protocol}://{domain}{path}"
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
            body_head = (r.text or "")[:20000].lower()
            if r.status_code == 200 and needle.lower() in body_head:
                finding = {
                    "path": path,
                    "url": r.url,
                    "status_code": r.status_code,
                    "cms": cms,
                    "severity": "critical",
                }
                out.append(finding)

                if ndjson_emit:
                    ndjson_emit({
                        "type": "SETUP_PAGE_EXPOSED",
                        "domain": domain,
                        **finding,
                    })
                logger.warning("CRITICAL: exposed %s setup page at %s", cms, r.url)

        except requests.exceptions.RequestException:
            continue
        except Exception as e:
            logger.debug("setup check error %s: %s", url, e)
    return domain, out


def detect_setup_pages(alive_hosts: list, rate_limiter=None) -> Dict[str, List[dict]]:
    """
    Returns {host: [ {path, url, status_code, cms, severity}, ... ]}
    Only reports pages that returned 200 AND actually contain the CMS marker
    (avoids false positives from soft-404 homepages).
    Hosts are probed concurrently to keep total runtime bounded.
    """
    results: Dict[str, List[dict]] = {}
    hosts = [h for h in (alive_hosts or [])]
    if not hosts:
        return results

    from concurrent.futures import ThreadPoolExecutor, as_completed

    with ThreadPoolExecutor(max_workers=min(4, len(hosts))) as ex:
        futures = [ex.submit(_audit_host_setup, h, rate_limiter) for h in hosts]
        for fut in as_completed(futures):
            try:
                domain, findings = fut.result()
                if domain and findings:
                    results[domain] = findings
            except Exception as e:
                logger.debug("setup audit failed: %s", e)
    return results
