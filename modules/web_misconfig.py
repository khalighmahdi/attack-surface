"""
modules/web_misconfig.py
=========================
Blue-Team CRITICAL: classic web misconfigurations, all non-destructive.

Checks per alive host:
  1. CORS wildcard with credentials
     - Origin: https://evil.example reflected with Access-Control-Allow-Credentials: true
       => attacker sites can read authenticated responses  (critical)
     - Access-Control-Allow-Origin: * on API endpoints (medium, contextual)
  2. TRACE method enabled (XST) — OPTIONS request advertising TRACE (medium)
  3. Directory listing — autoindex at / and /backup/, /files/ (medium)
  4. Exposed backup & sensitive files (HEAD requests only, never download):
     /backup.zip /backup.tar.gz /db.sql /database.sql /dump.sql
     /wp-config.php.bak /wp-config.php~ /.env /.env.backup /.git/config
     /config.php.bak /site.tar.gz /www.zip /administrator/backups/
     => CRITICAL when found (source/credentials exposure)
  5. Server-status / server-info pages (Apache) (low/medium)

Each finding is verified with a second request to avoid false positives.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger("AttackSurface.WebMisconf")

TIMEOUT = 5
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36", "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}

BACKUP_PATHS = [
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/site.zip",
    "/www.zip", "/db.sql", "/database.sql", "/dump.sql",
    "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.old",
    "/.env", "/.env.backup", "/.env.old", "/.git/config",
    "/config.php.bak", "/configuration.php.bak",
    "/administrator/backups/", "/web.config.bak",
]

# markers: path -> substring that proves exposure (avoid 200-but-not-really)
CONFIRM_MARKERS = {
    "/.git/config": ["[core]", "repositoryformatversion"],
    "/.env": ["DB_PASSWORD", "APP_KEY", "DATABASE_URL"],
    "/wp-config.php.bak": ["DB_PASSWORD", "DB_NAME", "table_prefix"],
    "/wp-config.php~": ["DB_PASSWORD", "DB_NAME"],
    "/wp-config.php.old": ["DB_PASSWORD", "DB_NAME"],
    "/config.php.bak": ["DB_"],
    "/configuration.php.bak": ["db", "password"],
    "/database.sql": ["CREATE TABLE", "INSERT INTO"],
    "/db.sql": ["CREATE TABLE", "INSERT INTO"],
    "/dump.sql": ["CREATE TABLE", "INSERT INTO"],
    "/backup.sql": ["CREATE TABLE", "INSERT INTO"],
}


def _head(url: str) -> requests.Response:
    return requests.head(url, timeout=TIMEOUT, headers=UA, allow_redirects=True)


def _get(url: str, **kw) -> requests.Response:
    kw.setdefault("timeout", TIMEOUT)
    kw.setdefault("headers", UA)
    return requests.get(url, **kw)


def check_cors(base_url: str) -> List[Dict[str, Any]]:
    out = []
    try:
        r = _get(base_url, headers={**UA, "Origin": "https://evil.example"})
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "https://evil.example" and acac.lower() == "true":
            out.append({"type": "CORS_CREDENTIALED_WILDCARD", "severity": "critical",
                        "evidence": f"ACAO={acao} ACAC={acac}"})
        elif acao == "*":
            out.append({"type": "CORS_WILDCARD", "severity": "info",
                        "evidence": "ACAO=* (context-dependent)"})
    except requests.RequestException:
        pass
    return out


def check_trace(base_url: str) -> List[Dict[str, Any]]:
    out = []
    try:
        r = requests.options(base_url, timeout=TIMEOUT, headers=UA)
        allow = r.headers.get("Allow", "") + " " + r.headers.get("Public", "")
        if "TRACE" in allow.upper():
            out.append({"type": "TRACE_ENABLED", "severity": "medium",
                        "evidence": f"Allow: {allow.strip()[:60]}"})
    except requests.RequestException:
        pass
    return out


def check_listing(base_url: str) -> List[Dict[str, Any]]:
    out = []
    for path in ("/", "/backup/", "/files/"):
        try:
            r = _get(base_url.rstrip("/") + path)
            body = r.text or ""
            if r.status_code == 200 and re.search(
                    r"Index of /|<title>Directory listing|Parent Directory", body, re.I):
                out.append({"type": "DIRECTORY_LISTING", "severity": "medium",
                            "evidence": base_url.rstrip("/") + path})
        except requests.RequestException:
            continue
    return out


def check_backups(base_url: str) -> List[Dict[str, Any]]:
    out = []
    for path in BACKUP_PATHS:
        url = base_url.rstrip("/") + path
        try:
            r = _head(url)
            if r.status_code == 405:  # some servers hate HEAD — try GET with small read
                r = _get(url, stream=True)
                ok = r.status_code == 200
                r.close()
            else:
                ok = r.status_code == 200
            if not ok:
                continue
            # catch-all routers (payment gateways, SPAs) return 200 text/html
            # for ANY path -> a real backup file has a binary/config content-type
            ctype = (r.headers.get("Content-Type") or "").lower()
            if "text/html" in ctype:
                continue
            # confirm with markers where known (avoid 200-custom-404 pages)
            markers = CONFIRM_MARKERS.get(path)
            if markers:
                g = _get(url)
                if not any(m in (g.text or "") for m in markers):
                    continue
            out.append({"type": "SENSITIVE_FILE_EXPOSED", "severity": "critical",
                        "evidence": url})
        except requests.RequestException:
            continue
    return out


def check_server_pages(base_url: str) -> List[Dict[str, Any]]:
    out = []
    for path, ftype in (("/server-status", "SERVER_STATUS"),
                        ("/server-info", "SERVER_INFO")):
        try:
            r = _get(base_url.rstrip("/") + path)
            if r.status_code == 200 and ("Apache Server Status" in r.text
                                          or "Server Information" in r.text):
                out.append({"type": ftype, "severity": "low",
                            "evidence": base_url.rstrip("/") + path})
        except requests.RequestException:
            continue
    return out


def check_ip_allowlist_bypass(base_url: str) -> List[Dict[str, Any]]:
    """Does the allowlist trust a client-supplied header?

    A site that "only lets one IP in" enforces that in one of two places:
    the network (firewall, security group) or the application (reading
    X-Forwarded-For and friends). Only the second is a defect, and this is
    how to tell them apart without exploiting anything:

      * beat 1 — plain GET, no extra header. If this is not a 401/403 the
        host is not gated at all and there is no allowlist to characterise.
      * beat 2 — the same GET plus a header claiming to be a trusted
        source. A change from blocked to 200 means the app is trusting a
        value the client controls, so anyone who can set a header is in.

    Read-only: the same GET is repeated with extra header values, which
    any HTTP client may do. Nothing is written to the target and no access
    control is modified. Reported only on an observed change, so a host
    filtered at the network layer stays silent.
    """
    out: List[Dict[str, Any]] = []

    # Header names real deployments read when deciding "is this client
    # internal?", with the values those checks usually trust.
    probe_headers = [
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Real-IP", "127.0.0.1"),
        ("X-Client-IP", "127.0.0.1"),
        ("X-Originating-IP", "127.0.0.1"),
        ("X-Remote-IP", "127.0.0.1"),
        ("X-Forwarded-Host", "localhost"),
        ("Forwarded", "for=127.0.0.1;proto=https"),
    ]

    def _attempt(extra: Optional[Dict[str, str]] = None):
        """One GET, reduced to the signals that tell blocked from allowed."""
        try:
            r = _get(base_url, headers={**UA, **(extra or {})})
            m = re.search(r"<title[^>]*>(.*?)</title>", r.text or "", re.I | re.S)
            return {"status": r.status_code, "length": len(r.content or b""),
                    "title": (m.group(1).strip()[:80] if m else "")}
        except requests.RequestException:
            return None

    base = _attempt()
    if not base or base["status"] not in (401, 403):
        return out

    for name, value in probe_headers:
        got = _attempt({name: value})
        if not got:
            continue
        if got["status"] == 200:
            out.append({
                "type": "IP_ALLOWLIST_HEADER_BYPASS",
                "severity": "high",
                "evidence": (f"{name}: {value} turns {base['status']} into 200 "
                             f"({base['length']}B -> {got['length']}B) — the "
                             f"application trusts a client-supplied header"),
            })
            break  # one proven bypass is the finding; more headers are noise
    return out


def check_ip_allowlist_enforcing(base_url: str) -> List[Dict[str, Any]]:
    """Report that a host IS gated, and by which layer.

    The complement of the bypass check, as an info note rather than a
    finding: knowing a host is filtered at the network (every forged
    header still 403) is useful coverage, because a correctly-protected
    host should not look identical to a broken scan.
    """
    out: List[Dict[str, Any]] = []
    try:
        r = _get(base_url)
        if r.status_code in (401, 403):
            out.append({
                "type": "IP_ALLOWLIST_ENFORCED",
                "severity": "info",
                "evidence": (f"HTTP {r.status_code} to an unlisted client and no "
                             f"forged header changed it — the filter sits at the "
                             f"network/proxy layer, not the application"),
            })
    except requests.RequestException:
        pass
    return out


def _audit_host(host, rate_limiter=None) -> List[Dict[str, Any]]:
    """Run all misconfiguration checks for a single host (thread-safe)."""
    findings: List[Dict[str, Any]] = []

    def _rl():
        if rate_limiter is not None:
            rate_limiter.wait()

    d = host.get("domain") if isinstance(host, dict) else host
    proto = host.get("protocol", "https") if isinstance(host, dict) else "https"
    if not d:
        return findings
    base = f"{proto}://{d}"
    bypass_found = False
    for check_fn in (check_cors, check_trace, check_listing,
                     check_backups, check_server_pages,
                     check_ip_allowlist_bypass):
        try:
            _rl()
            for f in check_fn(base):
                f["domain"] = d
                findings.append(f)
                if f.get("type") == "IP_ALLOWLIST_HEADER_BYPASS":
                    bypass_found = True
                logger.warning("MISCONFIG %s %s %s",
                               f.get("severity"), f.get("type"), d)
        except Exception as e:
            logger.debug("check %s on %s failed: %s", check_fn.__name__, d, e)
    # The "enforced at the network layer" note is a claim that the gate
    # held. It must never be emitted for a host where a forged header
    # just walked through — that would report the site as insulated and
    # bypassable in the same breath.
    if not bypass_found:
        try:
            _rl()
            for f in check_ip_allowlist_enforcing(base):
                f["domain"] = d
                findings.append(f)
        except Exception as e:
            logger.debug("allowlist enforcing check on %s failed: %s", d, e)
    return findings


def run_checks(alive_hosts: list, rate_limiter=None) -> List[Dict[str, Any]]:
    """Run all misconfiguration checks; returns flat findings list.

    Hosts are audited concurrently so a single slow/unreachable host cannot
    stall the whole phase (each request already has its own short timeout).
    """
    findings: List[Dict[str, Any]] = []
    hosts = list(alive_hosts or [])
    if not hosts:
        return findings
    from concurrent.futures import ThreadPoolExecutor, as_completed

    workers = min(4, len(hosts))
    try:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = [ex.submit(_audit_host, h, rate_limiter) for h in hosts]
            for fut in as_completed(futures):
                try:
                    findings.extend(fut.result())
                except Exception as e:
                    logger.debug("host audit failed: %s", e)
    except Exception as e:
        logger.debug("concurrent misconfig audit failed: %s", e)
    return findings
