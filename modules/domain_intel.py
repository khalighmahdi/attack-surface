"""
modules/domain_intel.py
========================
Blue-Team: brand & domain lifecycle intelligence.

1. Certificate Transparency watch (crt.sh)
   - Lists ALL certificates ever issued for the domain AND lookalikes
   - New/unknown issuances on sibling TLDs (domcn.com for domain.com)
     are the classic pre-phishing signal — check BEFORE the phish goes live
   - Compare against a local "known" snapshot (reports/ct_known.json)

2. WHOIS expiry + age
   - Flags domains expiring within 30 days (high) / 90 days (medium)
   - Very young domain (< 30d) flagged info (new infra?)
   - Uses python-whois if available; falls back to RDAP over HTTPS

Findings:
   CT_NEW_CERTIFICATE   (medium)  — cert not seen in previous snapshot
   CT_LOOKALIKE_CERT    (high)    — cert on a typosquat/lookalike domain
   WHOIS_EXPIRING_SOON  (high)
   WHOIS_EXPIRING       (medium)
   WHOIS_YOUNG_DOMAIN   (info)
"""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger("AttackSurface.DomainIntel")

CT_URL = "https://crt.sh/?q=%25.{domain}&output=json"
TIMEOUT = 30
CT_KNOWN = os.path.join("reports", "ct_known.json")

# lookalike generator: classic typosquats for a base domain
def _lookalikes(base: str, tld: str) -> List[str]:
    out = []
    for t in ("com", "net", "org", "ir", "io", "co"):
        if t != tld:
            out.append(f"{base}.{t}")
    out += [f"{base}s.{tld}", f"{base}-secure.{tld}", f"www-{base}.{tld}",
            f"{base}login.{tld}", f"{base}-login.{tld}", f"{base}pay.{tld}"]
    return out


def ct_watch(domain: str) -> Dict[str, Any]:
    res: Dict[str, Any] = {"domain": domain, "certificates": [], "new": [], "lookalikes": []}
    base, _, tld = domain.partition(".")
    try:
        r = requests.get(CT_URL.format(domain=domain), timeout=TIMEOUT,
                         headers={"User-Agent": "AttackSurfaceScanner/0.11"})
        entries = r.json() if r.status_code == 200 else []
    except Exception as e:
        res["error"] = str(e)[:120]
        return res

    seen: Dict[str, Dict[str, Any]] = {}
    for e in entries or []:
        name = (e.get("name_value") or "").split("\n")[0].lstrip("*.")
        if not name:
            continue
        ent = {
            "name": name,
            "issuer": (e.get("issuer_name") or "")[:80],
            "not_before": (e.get("not_before") or "")[:10],
        }
        seen[name] = ent
        res["certificates"].append(ent)

    # load known snapshot
    known: Dict[str, Any] = {}
    try:
        known = json.loads(open(CT_KNOWN, encoding="utf-8").read())
    except Exception:
        pass

    # new certs since last snapshot
    for name, ent in seen.items():
        if name not in known:
            res["new"].append(ent)

    # lookalike coverage
    for lk in _lookalikes(base, tld):
        for name, ent in seen.items():
            if name == lk or name.endswith("." + lk):
                ent2 = dict(ent)
                ent2["lookalike_of"] = domain
                res["lookalikes"].append(ent2)

    # save snapshot
    try:
        os.makedirs(os.path.dirname(CT_KNOWN), exist_ok=True)
        json.dump(seen, open(CT_KNOWN, "w"), ensure_ascii=False, indent=1)
    except Exception:
        pass
    return res


def whois_check(domain: str) -> Dict[str, Any]:
    res: Dict[str, Any] = {"domain": domain}
    expiry: Optional[datetime] = None
    created: Optional[datetime] = None
    try:
        import whois as _w  # python-whois
        w = _w.whois(domain)
        expiry = w.get("expiration_date")
        if isinstance(expiry, list):
            expiry = expiry[0]
        created = w.get("creation_date")
        if isinstance(created, list):
            created = created[0]
        res["registrar"] = w.get("registrar")
    except ImportError:
        # RDAP fallback (no external deps)
        try:
            tld = domain.rsplit(".", 1)[-1]
            # prefer authoritative registry RDAP (faster & more reliable than rdap.org)
            if tld in ("com", "net"):
                rdap_url = f"https://rdap.verisign.com/{tld}/v1/domain/{domain}"
            else:
                rdap_url = f"https://rdap.org/domain/{domain}"
            if rdap_url:
                r = requests.get(rdap_url, timeout=45,
                                 headers={"Accept": "application/rdap+json"})
                if r.status_code == 200:
                    d = r.json()
                    for ev in d.get("events", []):
                        if ev.get("eventAction") == "expiration":
                            expiry = datetime.fromisoformat(
                                ev["eventDate"].replace("Z", "+00:00"))
                        if ev.get("eventAction") == "registration":
                            created = datetime.fromisoformat(
                                ev["eventDate"].replace("Z", "+00:00"))
        except Exception as e:
            res["error"] = str(e)[:120]
            return res
    except Exception as e:
        res["error"] = str(e)[:120]
        return res

    now = datetime.now(timezone.utc)
    if expiry is not None:
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        days = (expiry - now).days
        res["expires_in_days"] = days
        if 0 < days <= 30:
            res["findings"] = [{"type": "WHOIS_EXPIRING_SOON", "severity": "high"}]
        elif 0 < days <= 90:
            res["findings"] = [{"type": "WHOIS_EXPIRING", "severity": "medium"}]
    if created is not None:
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_days = (now - created).days
        res["age_days"] = age_days
        if age_days < 30:
            res.setdefault("findings", []).append(
                {"type": "WHOIS_YOUNG_DOMAIN", "severity": "info"})
    return res


def run_checks(domain: str) -> Dict[str, Any]:
    out = {"ct": ct_watch(domain), "whois": whois_check(domain)}
    return out
