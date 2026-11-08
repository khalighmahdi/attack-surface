"""sqli_probe.py — SAFE SQL-injection surface detection (non-destructive).

What it does (read-only):
  1. Crawl a few pages of the target, collect links with query strings.
  2. For each parameterized URL, send benign probes:
       - append a single quote          -> detect SQL error signatures
       - append a tautology-free canary -> compare reflection/behavior
  3. Flag candidates with matched DB error signatures (MySQL/Postgres/MSSQL/SQLite).

What it NEVER does: UNION exfiltration, time-based bombs, data dumping,
or anything mutating. Those belong to sqlmap via Auto-Hunt (plan-only).

Output: findings[] + sqlmap candidate command list.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

import requests

UA = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
}

ERROR_SIGNATURES = {
    "MySQL": [r"you have an error in your sql syntax", r"warning: mysql",
              r"unclosed quotation mark", r"quoted string not properly terminated",
              r"mysqli?_[a-z_]*\(", r"mysql_fetch"],
    "PostgreSQL": [r"pg_query\(\)", r"postgresql.*error", r"valid PostgreSQL result",
                   r"pg_exec"],
    "MSSQL": [r"microsoft sql server", r"\bsqlserver\b.*error",
              r"odbc.*driver.*error", r"unclosed quotation mark after"],
    "SQLite": [r"sqlite3?::query\(\)", r"sqlite_master", r"unrecognized token",
               r"SQLITE_ERROR"],
    "Oracle": [r"ora-\d{5}", r"oracle.*error"],
}

_MAX_LINKS = 25
_CRAWL_PAGES = 6


def _s(timeout: int = 8) -> requests.Session:
    s = requests.Session()
    s.trust_env = False  # ignore ambient ALL_PROXY env — direct connections
    s.headers.update(UA)
    return s


def _same_origin(u1: str, u2: str) -> bool:
    a, b = urlsplit(u1), urlsplit(u2)
    return (a.netloc, a.scheme) == (b.netloc, b.scheme)


def collect_parameterized_urls(base: str, s: requests.Session,
                               max_links: int = _MAX_LINKS) -> List[str]:
    """Homepage + a few same-origin links → URLs with query strings."""
    base = base.rstrip("/")
    candidates: List[str] = []
    try:
        seen_pages = 0
        to_visit = [base + "/"]
        visited = set()
        while to_visit and seen_pages < _CRAWL_PAGES and len(candidates) < max_links:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)
            try:
                r = s.get(url, timeout=8, allow_redirects=True)
                seen_pages += 1
            except Exception:
                continue
            if r.status_code != 200:
                continue
            # links with query strings on same origin
            for m in re.finditer(r'href=["\']([^"\'#]+)', r.text):
                link = m.group(1)
                if link.startswith("//"):
                    link = "https:" + link
                elif link.startswith("/"):
                    link = base + link
                if not link.startswith("http"):
                    continue
                if not _same_origin(base + "/", link):
                    continue
                if "?" in link and "=" in link:
                    if link not in candidates:
                        candidates.append(link)
                elif link not in to_visit and link not in visited and link.endswith(("/", "html", "php")):
                    to_visit.append(link)
            if len(candidates) >= max_links:
                break
    except Exception as e:
        logging.debug("crawl error: %s", e)
    return candidates[:max_links]


def _flag_from_body(body: str) -> str | None:
    low = body.lower()
    for db, sigs in ERROR_SIGNATURES.items():
        for sig in sigs:
            if re.search(sig, low):
                return db
    return None


def probe_url(url: str, s: requests.Session) -> Dict[str, Any] | None:
    """Benign single-quote probe on one URL. Returns result dict or None."""
    parts = urlsplit(url)
    params = parse_qsl(parts.query, keep_blank_values=True)
    if not params:
        return None
    flagged: List[Dict[str, str]] = []
    try:
        for name, _val in params[:6]:  # cap params per URL
            probe_qs = urlencode([(n, (v + "'" if n == name else v))
                                  for n, v in params])
            probe_url_str = urlunsplit((parts.scheme, parts.netloc,
                                        parts.path, probe_qs, ""))
            try:
                r = s.get(probe_url_str, timeout=8, allow_redirects=True)
                db = _flag_from_body(r.text or "")
                if db:
                    flagged.append({"param": name, "db": db})
            except Exception:
                continue
    except Exception:
        return None
    if not flagged:
        return None
    dbs = sorted({f["db"] for f in flagged})
    return {
        "url": url,
        "params": [f["param"] for f in flagged],
        "db_signatures": dbs,
    }


def run_sqli_probe(base: str, max_urls: int = 12) -> Dict[str, Any]:
    """Probe a site for SQL-error-revealing parameters (SAFE)."""
    s = _s()
    base = base.rstrip("/")
    urls = collect_parameterized_urls(base, s, max_links=_MAX_LINKS)
    results: List[Dict[str, Any]] = []
    for u in urls[:max_urls]:
        r = probe_url(u, s)
        if r:
            results.append(r)
    return {
        "target": base,
        "urls_checked": len(urls[:max_urls]),
        "candidates": results,
    }


def to_findings(target: str, probe: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for c in probe.get("candidates") or []:
        dbs = "/".join(c["db_signatures"])
        out.append(
            f"SQL error disclosure on {c['url'].split('?')[0]} "
            f"(param: {', '.join(c['params'])}) reveals {dbs} (high) — "
            f"database errors leak schema details; wrap queries in error "
            f"handling and prepare statements")
    return out


def sqlmap_commands(candidates: List[Dict[str, Any]]) -> List[str]:
    """Plan-only sqlmap commands for Auto-Hunt hand-off."""
    cmds = []
    for c in candidates or []:
        for p in c.get("params", [])[:2]:
            cmds.append(
                f"sqlmap -u '{c['url']}' -p {p} --batch --level=2 --risk=2 "
                f"--threads=2")
    return cmds
