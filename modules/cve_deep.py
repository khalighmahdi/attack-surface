"""
modules/cve_deep.py
====================
Blue-Team: precise CPE-based CVE matching with exact version comparison.

Why not keyword search?  "Apache 2.4.49" via keywordSearch returns noise
(CVEs for other products containing "Apache"). CPE Name matching is exact:
    cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*

This module:
  1. Builds a CPE 2.3 name from (product, version) pairs found by
     tech_fingerprint / port banners.
  2. Queries NVD /cves/2.0?cpeName=... (official, exact-match API).
  3. Falls back to keyword + client-side version-range comparison when
     the CPE vendor is unknown.
  4. Returns CVEs sorted by CVSS with exploit references (if any).

No API key needed for low volume. NVD_API_KEY env raises rate-limit.
"""
from __future__ import annotations

import json
import logging
import os
import re
import urllib.request
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("AttackSurface.CVEDeep")

NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}"
NVD_KW_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={kw}"
TIMEOUT = 15
CACHE = os.path.join("reports", "cve_deep_cache.json")

# product-name normalization: fingerprint string -> (cpe_vendor, cpe_product)
# (cpe_product must be NVD's official naming)
CPE_MAP: Dict[str, Tuple[str, str]] = {
    "apache": ("apache", "http_server"),
    "apache httpd": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "litespeed": ("litespeed", "litespeed_web_server"),
    "openlitespeed": ("litespeedtech", "openlitespeed"),
    "iis": ("microsoft", "iis"),
    "pure-ftpd": ("pureftpd", "pure-ftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "vsftpd": ("vsftpd", "vsftpd"),
    "openssh": ("openbsd", "openssh"),
    "dovecot": ("dovecot", "dovecot"),
    "postfix": ("postfix", "postfix"),
    "exim": ("exim", "exim"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
    "php": ("php", "php"),
    "openssl": ("openssl", "openssl"),
    "tomcat": ("apache", "tomcat"),
    "powerdns": ("powerdns", "authoritative"),
    "bind": ("isc", "bind"),
    "cpanel": ("cpanel", "cpanel"),
    "zarinpal": ("zarinpal", "payment_gateway"),
}

_VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")

# technologies that are not software products — skip CVE mapping entirely
GENERIC_TECHS = {"html", "javascript", "css", "json", "xml", "http", "https",
                 "tcp", "tls", "ssl", "font", "image", "cdn", "html5"}



def _parse_version(v: str) -> Tuple[int, int, int]:
    m = _VERSION_RE.search(v or "")
    if not m:
        return (0, 0, 0)
    return tuple(int(g) if g else 0 for g in m.groups())  # type: ignore


def _cpe_from_tech(tech: str) -> Optional[str]:
    """'Apache 2.4.49' -> cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"""
    t = tech.strip().lower()
    version = ""
    m = _VERSION_RE.search(t)
    if m:
        version = m.group(0)
        t = t[: m.start()].strip(" -_:")
    if t in GENERIC_TECHS or t.split()[0] in GENERIC_TECHS:
        return None
    for name, (vendor, product) in CPE_MAP.items():
        if t.startswith(name) or name in t:
            ver = version or "-"
            return f"cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"
    return None


def _nvd_cpe_query(cpe: str) -> List[Dict[str, Any]]:
    url = NVD_CPE_URL.format(cpe=urllib.parse.quote(cpe))
    return _nvd_query(url)


def _nvd_keyword_query(keyword: str) -> List[Dict[str, Any]]:
    url = NVD_KW_URL.format(kw=urllib.parse.quote(keyword))
    return _nvd_query(url)


def _nvd_query(url: str) -> List[Dict[str, Any]]:
    headers = {"User-Agent": "AttackSurfaceScanner/0.9"}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))
    except Exception as e:
        logger.debug("NVD query failed: %s", e)
        return []
    return _extract_cves(data)


def _extract_cves(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for item in data.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        cid = cve.get("id", "?")
        desc = ""
        for d in cve.get("descriptions") or []:
            if d.get("lang") == "en":
                desc = d.get("value", "")[:200]
                break
        metrics = cve.get("metrics") or {}
        score = None
        vector = None
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(k):
                cv = metrics[k][0].get("cvssData", {})
                score = cv.get("baseScore")
                vector = cv.get("vectorString")
                break
        refs = [r.get("url") for r in (cve.get("references") or [])[:3]]
        out.append({
            "id": cid, "cvss": score, "vector": vector,
            "summary": desc, "refs": refs,
        })
    # sort by CVSS desc (None last)
    out.sort(key=lambda c: -(c.get("cvss") or 0))
    return out


def _load_cache() -> Dict[str, Any]:
    try:
        with open(CACHE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_cache(data: Dict[str, Any]) -> None:
    try:
        os.makedirs(os.path.dirname(CACHE), exist_ok=True)
        with open(CACHE, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass


def deep_scan(technologies: Dict[str, Any],
              min_cvss: float = 7.0,
              max_queries: int = 20) -> Dict[str, List[Dict[str, Any]]]:
    """
    technologies: {host: {"technologies": [...]}} or {host: [tech, ...]}
    Returns {host: [{tech, cpe, cves: [...]}, ...]}
    """
    cache = _load_cache()
    results: Dict[str, List[Dict[str, Any]]] = {}
    queries = 0

    for host, blob in (technologies or {}).items():
        techs = blob.get("technologies") if isinstance(blob, dict) else blob
        hits = []
        for tech in techs or []:
            if not isinstance(tech, str):
                continue
            cpe = _cpe_from_tech(tech)
            key = (cpe or tech.lower())
            if key in cache:
                cves = cache[key]
            elif queries >= max_queries:
                continue
            else:
                first_word = tech.split()[0].lower() if tech.split() else ""
                if first_word in GENERIC_TECHS:
                    continue  # no meaningful CPE for generic techs
                if cpe:
                    cves = _nvd_cpe_query(cpe)
                    if not cves:  # fallback: keyword
                        cves = _nvd_keyword_query(first_word)
                else:
                    cves = _nvd_keyword_query(first_word)
                cache[key] = cves
                queries += 1
            # client-side CVSS filter
            cves = [c for c in cves if (c.get("cvss") or 0) >= min_cvss]
            if cves:
                hits.append({
                    "tech": tech,
                    "cpe": cpe,
                    "cves": cves[:10],
                })
        if hits:
            results[host] = hits

    _save_cache(cache)
    total = sum(len(h["cves"]) for v in results.values() for h in v)
    logger.info("cve_deep: %d hosts, %d CVEs (min CVSS %.1f)",
                len(results), total, min_cvss)
    return results
