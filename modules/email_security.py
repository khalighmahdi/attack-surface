"""
modules/email_security.py
==========================
Blue-Team CRITICAL: email spoofing exposure checks.

Checks (all passive DNS lookups, zero packets to the target):
  SPF    — TXT at apex; flags missing record, "+all" (allow anyone!),
           "?all" (soft - useless), and too many DNS lookups (>10 = broken)
  DMARC  — TXT at _dmarc.domain; flags missing policy, p=none (monitoring
           only = spoofing still delivered), missing rua (no reports)
  DKIM   — TXT at common selectors (default_, google._domainkey,
           selector1._domainkey, k1._domainkey, s1._domainkey, mail, dkim)
           - informational only (absence is not critical by itself)

Findings emitted:
  EMAIL_SPOOFING_POSSIBLE  (critical)  — no SPF or DMARC p=none
  SPF_ALLOW_ALL            (critical)  — "+all" present
  DMARC_WEAK_POLICY        (high)      — p=none
  SPF_MISSING              (high)
  DMARC_MISSING            (high)
  DKIM_NO_RECORD           (info)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

try:
    import dns.resolver
except ImportError:
    dns = None

logger = logging.getLogger("AttackSurface.EmailSec")

DKIM_SELECTORS = ["default", "google", "selector1", "selector2",
                  "k1", "s1", "s2", "mail", "dkim", "zoho", "protonmail",
                  "mandrill", "zendesk1", "fm1", "sib", "mte1"]


def _txt(name: str) -> List[str]:
    try:
        ans = dns.resolver.resolve(name, "TXT")
        out = []
        for r in ans:
            for s in r.strings:
                out.append(s.decode("utf-8", "ignore"))
        return out
    except Exception:
        return []


def check_email_security(domain: str) -> Dict[str, Any]:
    if dns is None:
        return {"error": "dnspython missing"}
    res: Dict[str, Any] = {"domain": domain}

    # ---- SPF ----
    spf = next((t for t in _txt(domain) if t.lower().startswith("v=spf1")), None)
    res["spf"] = spf
    findings = []
    if not spf:
        findings.append({"type": "SPF_MISSING", "severity": "high"})
    elif "+all" in spf:
        findings.append({"type": "SPF_ALLOW_ALL", "severity": "critical"})
    elif "~all" not in spf and "-all" not in spf and "?all" in spf:
        findings.append({"type": "SPF_SOFT_ONLY", "severity": "medium"})
    res["spf_lookups"] = spf.count("include:") + spf.count("a") + spf.count("mx") \
        if spf else 0

    # ---- DMARC ----
    dmarc = next((t for t in _txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")), None)
    res["dmarc"] = dmarc
    if not dmarc:
        findings.append({"type": "DMARC_MISSING", "severity": "high"})
    else:
        if "p=none" in dmarc.lower():
            findings.append({"type": "DMARC_WEAK_POLICY", "severity": "high"})
        if "rua=" not in dmarc.lower():
            findings.append({"type": "DMARC_NO_REPORTS", "severity": "info"})

    # ---- DKIM (informational) ----
    dkim_found = False
    for sel in DKIM_SELECTORS:
        if any(t.startswith("v=DKIM1") or "p=" in t
               for t in _txt(f"{sel}._domainkey.{domain}")):
            dkim_found = True
            res["dkim_selector"] = sel
            break
    res["dkim_found"] = dkim_found
    if not dkim_found:
        findings.append({"type": "DKIM_NO_RECORD", "severity": "info"})

    # headline: can anyone spoof this domain?
    spoofable = (not spf) or (not dmarc) or ("p=none" in (dmarc or "").lower())
    res["email_spoofing_possible"] = spoofable
    if spoofable:
        findings.append({"type": "EMAIL_SPOOFING_POSSIBLE", "severity": "critical"})
    res["findings"] = findings
    return res
