"""vuln_intel.py — Vulnerability Intelligence Layer.

Enriches CVEs with EPSS, CISA KEV, Exploit-DB, Metasploit, and MITRE ATT&CK,
and computes a contextual risk score:

    risk = CVSS * EPSS_weight * KEV_boost * exploit_boost

Fail-soft: every remote lookup is cached to ~/.cache/attack-surface/vuln_intel.json
and on network failure falls back to CVSS-only scoring.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional

CACHE = Path(os.path.expanduser("~/.cache/attack-surface/vuln_intel.json"))
CACHE_TTL = 12 * 3600  # 12h

EPSS_URL = "https://api.first.org/data/v1/epss?cve={cve}"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EDB_API = "https://www.exploit-db.com/api/v1/search?cve={cve}"  # returns JSON with EDB-ID
MSF_API = "https://www.rapid7.com/db/api/v1/search?q={cve}&type=exploit"  # returns MSF modules
MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _load_cache() -> Dict[str, Any]:
    try:
        if CACHE.exists():
            data = json.loads(CACHE.read_text())
            if time.time() - data.get("_fetched", 0) < CACHE_TTL:
                return data
    except Exception:
        pass
    return {"_fetched": 0, "epss": {}, "kev_map": {}, "edb": {}, "msf": {}, "mitre": {}}


def _save_cache(data: Dict[str, Any]) -> None:
    try:
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        data["_fetched"] = time.time()
        data["kev_map"] = data.get("kev_map", {})
        CACHE.write_text(json.dumps(data))
    except Exception:
        pass


def _fetch_json(url: str, timeout: int = 15) -> Any:
    import requests
    return requests.get(url, timeout=timeout,
                        headers={"User-Agent": "Mozilla/5.0"}).json()


def _fetch_url(url: str, timeout: int = 15) -> str:
    """Fetch raw text/JSON from URL with Chrome UA."""
    import requests
    return requests.get(url, timeout=timeout,
                        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}).text


def load_kev(force: bool = False) -> Dict[str, Dict[str, Any]]:
    """CISA Known Exploited Vulnerabilities → {cve: {dateAdded, dueDate,...}}"""
    data = _load_cache()
    if data.get("kev_map") and not force:
        return data["kev_map"]
    try:
        j = _fetch_json(KEV_URL, timeout=30)
        kev_map = {v["cveID"]: v for v in j.get("vulnerabilities", [])}
        data["kev_map"] = kev_map
        _save_cache(data)
        logging.info("KEV loaded: %d entries", len(kev_map))
        return kev_map
    except Exception as e:
        logging.warning("KEV fetch failed: %s", e)
        return data.get("kev_map") or {}


def get_epss(cve: str) -> float | None:
    """EPSS probability (0..1) for a CVE; None if unavailable."""
    data = _load_cache()
    epss = data.setdefault("epss", {})
    if cve in epss:
        return epss[cve]
    try:
        j = _fetch_json(EPSS_URL.format(cve=cve))
        rows = j.get("data") or []
        val = float(rows[0]["epss"]) if rows else None
        epss[cve] = val
        _save_cache(data)
        return val
    except Exception:
        return None


def get_edb_info(cve: str) -> Optional[Dict[str, Any]]:
    """Exploit-DB info for a CVE: {edb_id, title, type, platform, url}."""
    data = _load_cache()
    edb = data.setdefault("edb", {})
    cve_upper = cve.upper()
    if cve_upper in edb:
        return edb[cve_upper]
    try:
        # Exploit-DB public API
        url = f"https://www.exploit-db.com/search?cve={cve}&format=json"
        txt = _fetch_url(url, timeout=20)
        j = json.loads(txt)
        for item in j.get("data", []):
            if cve_upper in str(item).upper():
                edb[cve_upper] = {
                    "edb_id": item.get("id"),
                    "title": item.get("title"),
                    "type": item.get("type"),
                    "platform": item.get("platform"),
                    "url": f"https://www.exploit-db.com/exploits/{item.get('id')}"
                }
                _save_cache(data)
                return edb[cve_upper]
    except Exception:
        pass
    return None


def get_msf_modules(cve: str) -> List[Dict[str, Any]]:
    """Metasploit modules for a CVE: [{name, path, rank, disclosure_date, url}]."""
    data = _load_cache()
    msf = data.setdefault("msf", {})
    cve_upper = cve.upper()
    if cve_upper in msf:
        return msf[cve_upper]
    try:
        # Rapid7 public API
        url = f"https://www.rapid7.com/db/api/v1/search?q={cve}&type=exploit"
        txt = _fetch_url(url, timeout=20)
        j = json.loads(txt)
        modules = []
        for item in j.get("results", []):
            if cve_upper in str(item).upper():
                modules.append({
                    "name": item.get("title"),
                    "path": item.get("metasploit", {}).get("path"),
                    "rank": item.get("metasploit", {}).get("rank"),
                    "disclosure_date": item.get("metasploit", {}).get("disclosure_date"),
                    "url": f"https://www.rapid7.com/db/modules/{item.get('metasploit', {}).get('path', '').replace('/', '-')}"
                })
        msf[cve_upper] = modules
        _save_cache(data)
        return modules
    except Exception:
        return []


def get_mitre_techniques(cve: str) -> List[Dict[str, Any]]:
    """MITRE ATT&CK techniques associated with a CVE (via CAPEC->ATT&CK mapping)."""
    data = _load_cache()
    mitre = data.setdefault("mitre", {})
    cve_upper = cve.upper()
    if cve_upper in mitre:
        return mitre[cve_upper]
    try:
        # Use NVD CVE -> CAPEC -> ATT&CK mapping (simplified: fetch from MITRE STIX)
        # For now, return empty - full implementation needs NVD CAPEC refs + MITRE STIX parsing
        mitre[cve_upper] = []
        _save_cache(data)
        return []
    except Exception:
        return []


def enrich_cve(cve_id: str, base_cvss: float | None,
               kev_map: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Full intel for one CVE."""
    kev_map = kev_map if kev_map is not None else load_kev()
    kev = kev_map.get(cve_id.upper())
    epss = get_epss(cve_id)
    edb = get_edb_info(cve_id)
    msf = get_msf_modules(cve_id)
    mitre = get_mitre_techniques(cve_id)
    cvss = base_cvss or 0.0

    # contextual score: KEV dominates (actively exploited = top priority),
    # EPSS scales the rest. Exploit availability adds boost.
    epss = epss if epss is not None else 0.0
    exploit_boost = 1.0
    if edb:
        exploit_boost *= 1.2
    if msf:
        exploit_boost *= 1.3
    if kev:
        risk = round(min(90.0 + epss * 10, 100.0), 1)  # 90-100 band
    else:
        risk = round(cvss * (1.0 + epss * 2.0) * exploit_boost, 1)  # up to ~3x CVSS

    return {
        "cve": cve_id,
        "cvss": cvss,
        "epss": epss,                            # 0..1 or None
        "kev": bool(kev),
        "kev_date_added": (kev or {}).get("dateAdded"),
        "kev_due": (kev or {}).get("dueDate"),
        "exploitdb": edb,
        "metasploit": msf,
        "mitre": mitre,
        "contextual_risk": min(risk, 100.0),
    }


def enrich_cve_list(cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """cves: [{id|cve, cvss, summary?...}] → enriched, sorted by contextual risk."""
    kev_map = load_kev()
    out = []
    for c in cves or []:
        cid = (c.get("id") or c.get("cve") or "")
        m = _CVE_RE.search(str(cid))
        if not m:
            continue
        e = enrich_cve(m.group(0).upper(), c.get("cvss"), kev_map)
        e["summary"] = c.get("summary") or ""
        out.append(e)
    out.sort(key=lambda x: x["contextual_risk"], reverse=True)
    return out
