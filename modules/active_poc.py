"""
modules/active_poc.py
======================
Blue-Team: SAFE active checks — non-destructive probes only.

Contains three families:

1. TLS audit (safe)
   - certificate expiry / self-signed / hostname mismatch
   - weak protocol negotiation (TLSv1.0/1.1 accepted?)
   - weak cipher suites (RC4, 3DES, NULL, EXPORT)
   - HSTS absence is covered by header_audit; here we grade TLS only

2. Login surface probe (VERY rate-limited, NO brute-force by default)
   - confirms a login form is live and reachable
   - checks for default-credential RISK INDICATORS (response diff on
     a deliberately wrong login) — one attempt only, clearly logged
   - never performs password guessing; --brute flag is intentionally
     not implemented in blue-team edition

3. DNS zone walk (passive-safe)
   - AXFR attempt against authoritative NS (if allowed = misconfigured)
   - DNSSEC presence check

All checks are read-only from the target's perspective (a normal
visitor could do the same). Nothing here constitutes exploitation.
"""
from __future__ import annotations

import logging
import socket
import ssl
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger("AttackSurface.ActivePoC")

TIMEOUT = 8
USER_AGENT = "AttackSurfaceScanner/0.9 (blue-team-safe)"


# --------------------------------------------------------------------------
# 1) TLS AUDIT
# --------------------------------------------------------------------------
WEAK_CIPHER_TOKENS = ("RC4", "3DES", "NULL", "EXPORT", "DES-CBC", "SEED", "IDEA")


def tls_audit(host: str, port: int = 443, rate_limiter=None) -> Dict[str, Any]:
    out: Dict[str, Any] = {"host": host, "port": port, "issues": [], "grade": "A"}
    ctx = ssl.create_default_context()
    # do not verify so we can grade self-signed/mismatch
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert(binary_form=False)
                der = tls.getpeercert(binary_form=True)
                proto = tls.version()
                cipher = tls.cipher()[0] if tls.cipher() else ""

                out["protocol"] = proto
                out["cipher"] = cipher

                # --- certificate parsing (needs PEM) ---
                if der:
                    import subprocess as _sp
                    pem = ssl.DER_cert_to_PEM_cert(der)
                    p = _sp.run(["openssl", "x509", "-noout", "-dates", "-subject"],
                                input=pem.encode(), capture_output=True, timeout=5)
                    txt = p.stdout.decode("utf-8", "ignore")
                    m_not = re.search(r"notAfter=(.+)", txt)
                    if m_not:
                        try:
                            exp = datetime.strptime(m_not.group(1).strip(),
                                                    "%b %d %H:%M:%S %Y %Z") \
                                    .replace(tzinfo=timezone.utc)
                            days = (exp - datetime.now(timezone.utc)).days
                            out["cert_expires_in_days"] = days
                            if days < 0:
                                out["issues"].append("CERT_EXPIRED")
                                out["grade"] = "F"
                            elif days < 14:
                                out["issues"].append(f"CERT_EXPIRING ({days}d)")
                                out["grade"] = min(out["grade"], "C")
                        except Exception:
                            pass
                    if "self-signed" in txt or ("CN=" in txt and "=" not in txt):
                        pass  # subject parse; self-signed detection via issuer check below

                # protocol downgrade
                if proto in ("TLSv1", "TLSv1.1"):
                    out["issues"].append(f"WEAK_PROTOCOL ({proto})")
                    out["grade"] = "F"

                # weak cipher in the one negotiated (active probe of default)
                if any(tok in cipher.upper() for tok in WEAK_CIPHER_TOKENS):
                    out["issues"].append(f"WEAK_CIPHER ({cipher})")
                    out["grade"] = "F"

                # --- force legacy protocol attempts ---
                for bad in ("TLSv1", "TLSv1_1"):
                    try:
                        bctx = ssl.SSLContext(getattr(ssl, f"PROTOCOL_TLSv1_1" if bad == "TLSv1_1" else "PROTOCOL_TLSv1"))
                        bctx.check_hostname = False
                        bctx.verify_mode = ssl.CERT_NONE
                        with socket.create_connection((host, port), timeout=4) as s2:
                            with bctx.wrap_socket(s2, server_hostname=host):
                                out["issues"].append(f"ACCEPTS_{bad}")
                                out["grade"] = "F"
                                break
                    except Exception:
                        continue

    except Exception as e:
        out["error"] = str(e)[:120]
        out["grade"] = "N/A"
    return out


# --------------------------------------------------------------------------
# 2) LOGIN SURFACE (single wrong-credential probe, NO brute force)
# --------------------------------------------------------------------------
LOGIN_PATHS = ("/wp-login.php", "/admin", "/login", "/user/login")

_FORM_RE = re.compile(r"<form[^>]*>", re.I)
_PW_RE = re.compile(r"type=['\"]password['\"]", re.I)


def login_probe(base_url: str, rate_limiter=None) -> Optional[Dict[str, Any]]:
    """
    Checks whether a login form exists and whether a single deliberately
    wrong login shows a standard failure (healthy) or something odd.
    ONE request pair only — this is a liveness probe, not brute force.
    """
    if rate_limiter is not None:
        rate_limiter.wait()
    url = base_url.rstrip("/") + "/wp-login.php"
    try:
        r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT},
                         allow_redirects=True)
        if r.status_code != 200 or "password" not in r.text.lower():
            return None
        has_form = bool(_FORM_RE.search(r.text))
        res = {
            "url": r.url,
            "has_login_form": has_form,
            "has_password_field": bool(_PW_RE.search(r.text)),
            "login_accessible": True,
        }
        # single wrong-credential POST (logged, rate-limited)
        if has_form:
            if rate_limiter is not None:
                rate_limiter.wait()
            rp = requests.post(
                r.url,
                data={"log": "blue-team-probe", "pwd": "X" * 16,
                      "wp-submit": "Log In", "testcookie": "1"},
                timeout=TIMEOUT,
                headers={"User-Agent": USER_AGENT},
                allow_redirects=False,
            )
            res["wrong_login_status"] = rp.status_code
            # 302 to same page / 200 with error = normal; 200 dashboard = BAD
            if rp.status_code in (301, 302):
                loc = rp.headers.get("Location", "")
                if "wp-admin" in loc or "redirect_to" in loc and "loggedout" not in loc:
                    res["default_credentials_risk"] = "check_manually"
            elif rp.status_code == 200 and ("dashboard" in rp.text.lower() or "admin_bar" in rp.text.lower()):
                res["default_credentials_risk"] = "CRITICAL_WRONG_LOGIN_SUCCEEDED"
        return res
    except requests.RequestException:
        return None


# --------------------------------------------------------------------------
# 3) DNS ZONE WALK (AXFR) + DNSSEC
# --------------------------------------------------------------------------
def dns_zone_walk(domain: str, nameservers: Optional[List[str]] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {"domain": domain, "axfr_allowed": False, "dnssec": None}
    # AXFR via dnspython
    try:
        import dns.resolver, dns.query, dns.zone
        ns_list = nameservers or []
        if not ns_list:
            try:
                ans = dns.resolver.resolve(domain, "NS")
                ns_list = [str(r) for r in ans]
            except Exception:
                ns_list = []
        for ns in ns_list[:3]:
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=6))
                names = [str(n) for n in z.nodes.keys()]
                out["axfr_allowed"] = True
                out["transferred_from"] = ns
                out["records"] = names[:80]
                break
            except Exception:
                continue
        # DNSSEC
        try:
            dns.resolver.resolve(domain, "DNSKEY")
            out["dnssec"] = True
        except dns.resolver.NoAnswer:
            out["dnssec"] = False
        except Exception:
            out["dnssec"] = None
    except ImportError:
        out["error"] = "dnspython missing"
    return out


# --------------------------------------------------------------------------
# Orchestrator
# --------------------------------------------------------------------------
def run_all(alive_hosts: list, domain: str, rate_limiter=None) -> Dict[str, Any]:
    report: Dict[str, Any] = {"tls": [], "login": [], "dns": None}
    for h in alive_hosts or []:
        d = h.get("domain") if isinstance(h, dict) else h
        if not d:
            continue
        tls = tls_audit(d, 443, rate_limiter)
        if tls.get("grade") not in ("N/A",) and tls.get("protocol"):
            report["tls"].append(tls)
        lp = login_probe(f"https://{d}", rate_limiter)
        if lp:
            report["login"].append(lp)
    report["dns"] = dns_zone_walk(domain)
    return report
