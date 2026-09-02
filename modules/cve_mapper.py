"""
modules/cve_mapper.py
======================
Blue-Team: map fingerprinted technologies to known CVEs via the
NVD public API (no key needed for low volume; set NVD_API_KEY env
for higher rate-limits).

Strategy:
  1. tech_fingerprint produces {host: ["Apache 2.4.49", "PHP 7.4", ...]}
  2. For each tech with a version, query NVD CPE-less keyword search
     and keep CVEs with CVSS >= 7 (configurable).
  3. Cache results in reports/cve_cache.json so repeated scans are polite.

This is a WATCHLIST, not a vulnerability scan — results guide patching.
"""
from __future__ import annotations

import json
import logging
import os
import re
import urllib.request
import urllib.parse
from typing import Any, Dict, List

logger = logging.getLogger("AttackSurface.CVE")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={kw}&cvssV3Severity={sev}"
CACHE = os.path.join("reports", "cve_cache.json")
DEFAULT_MIN_SEVERITY = "HIGH"
TIMEOUT = 15

_TECH_RE = re.compile(r"([A-Za-z][A-Za-z0-9._\- ]{1,30}?)\s*([0-9]+(?:\.[0-9]+){0,2})$")


def _cache_load() -> Dict[str, Any]:
    try:
        with open(CACHE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _cache_save(data: Dict[str, Any]) -> None:
    try:
        os.makedirs(os.path.dirname(CACHE), exist_ok=True)
        with open(CACHE, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass


def _parse_tech(tech: str):
    """'Apache 2.4.49' -> ('Apache', '2.4.49'); 'WordPress' -> ('WordPress', None)"""
    m = _TECH_RE.search(tech.strip())
    if m:
        return m.group(1).strip(), m.group(2)
    return tech.strip(), None


def _nvd_search(keyword: str, min_severity: str) -> List[Dict[str, Any]]:
    url = NVD_URL.format(kw=urllib.parse.quote(keyword), sev=min_severity)
    api_key = os.environ.get("NVD_API_KEY")
    headers = {"User-Agent": "AttackSurfaceScanner/0.8"}
    if api_key:
        headers["apiKey"] = api_key
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))
    except Exception as e:
        logger.debug("NVD query failed for %r: %s", keyword, e)
        return []

    out = []
    for item in (data.get("vulnerabilities") or []):
        cve = (item.get("cve") or {})
        cid = cve.get("id", "?")
        desc = ""
        for d in (cve.get("descriptions") or []):
            if d.get("lang") == "en":
                desc = d.get("value", "")[:200]
                break
        metrics = (cve.get("metrics") or {})
        score = None
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(k):
                score = metrics[k][0].get("cvssData", {}).get("baseScore")
                break
        out.append({"id": cid, "cvss": score, "summary": desc})
    return out


def map_cves(technologies: Dict[str, List[str]],
             min_severity: str = DEFAULT_MIN_SEVERITY,
             max_queries: int = 25) -> Dict[str, List[Dict[str, Any]]]:
    """
    technologies: {host: [tech, ...]} from tech_fingerprint
    returns:      {host: [{tech, cves: [...]}, ...]}
    """
    cache = _cache_load()
    results: Dict[str, List[Dict[str, Any]]] = {}
    queries = 0

    for host, techs in (technologies or {}).items():
        host_hits = []
        for tech in techs or []:
            name, _ver = _parse_tech(tech)
            if not name or len(name) < 3:
                continue
            key = f"{name.lower()}|{min_severity.lower()}"
            if key in cache:
                cves = cache[key]
            elif queries >= max_queries:
                continue  # stay polite; next run fills more of the cache
            else:
                cves = _nvd_search(name, min_severity)
                cache[key] = cves
                queries += 1
            if cves:
                host_hits.append({"tech": tech, "cves": cves[:8]})
        if host_hits:
            results[host] = host_hits

    _cache_save(cache)
    return results
