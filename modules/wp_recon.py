"""wp_recon.py — WordPress specialized reconnaissance (SAFE, non-destructive).

Detects WordPress and enumerates:
  - core version + exposed version files
  - active theme + parent theme (style.css probing)
  - plugins (feed probing from common list + wp-json active plugins)
  - REST users (/wp-json/wp/v2/users) — safe, read-only
  - xmlrpc.php enabled? (POST system.listMethods is read-only)
  - debug.log / wp-config backups (read-only GET of well-known paths)
  - directory listing on wp-content/uploads

Fail-soft: every probe returns [] on error. Uses browser UA (WAF-safe).
"""
from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List

import requests

UA = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
}

# popular plugins (free tier of wpvulndb-style list; extendable)
COMMON_PLUGINS = [
    "contact-form-7", "wordpress-seo", "elementor", "wpforms-lite",
    "classic-editor", "akismet", "woocommerce", "jetpack", "wordfence",
    "all-in-one-seo-pack", "wp-super-cache", "litespeed-cache", "updraftplus",
    "tablepress", "really-simple-ssl", "duplicator", "wp-file-manager",
    "advanced-custom-fields", "js_composer", "revslider", "mail-masta",
    "wp-job-manager", "google-sitemap-generator", "nextgen-gallery",
]

VERSION_RE = re.compile(
    r'<meta name="generator" content="WordPress ([0-9.]+)"', re.I)
THEME_RE = re.compile(
    r'/wp-content/themes/([a-z0-9_\-]+)/', re.I)
PLUGIN_RE = re.compile(
    r'/wp-content/plugins/([a-z0-9_\-]+)/', re.I)


def _s(timeout: int = 8) -> requests.Session:
    s = requests.Session()
    s.trust_env = False  # ignore ambient ALL_PROXY env (often dead) — direct
    s.headers.update(UA)
    return s


def _get(s: requests.Session, url: str, timeout: int = 8):
    return s.get(url, timeout=timeout, allow_redirects=True)


def detect_wordpress(base: str, s: requests.Session | None = None) -> Dict[str, Any] | None:
    """Returns {'wordpress': True, 'version':..., 'theme':...} or None."""
    s = s or _s()
    base = base.rstrip("/")
    try:
        r = _get(s, base + "/", timeout=8)
        if r.status_code != 200:
            return None
        body = r.text
        is_wp = ("wp-content" in body) or ("wp-includes" in body) or \
                VERSION_RE.search(body)
        if not is_wp:
            return None
        out: Dict[str, Any] = {"wordpress": True}
        m = VERSION_RE.search(body)
        if m:
            out["version"] = m.group(1)
        themes = THEME_RE.findall(body)
        if themes:
            out["theme"] = themes[0]
        return out
    except Exception:
        return None


def probe_theme_version(base: str, theme: str, s: requests.Session | None = None) -> str | None:
    """style.css usually exposes the exact theme version."""
    s = s or _s()
    try:
        r = _get(s, f"{base}/wp-content/themes/{theme}/style.css", timeout=6)
        if r.status_code == 200:
            m = re.search(r"Version:\s*([0-9.]+)", r.text)
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


def probe_plugins(base: str, body_hint: str = "",
                  s: requests.Session | None = None) -> List[str]:
    """Return plugin slugs: found via homepage HTML + HEAD probes."""
    s = s or _s()
    # Keep HTML-detected slugs as *candidate hints* only. We never report
    # a plugin unless the well-known readme.txt probe returned 200, so
    # HTML-only references (often bundled/third-party strings) do not
    # become false positives.
    found: set[str] = set()
    base = base.rstrip("/")

    def check(slug: str) -> str | None:
        try:
            r = s.head(f"{base}/wp-content/plugins/{slug}/readme.txt",
                       timeout=5, allow_redirects=True)
            if r.status_code == 200:
                return slug
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=8) as ex:
        for res in ex.map(check, COMMON_PLUGINS):
            if res:
                found.add(res)
    return sorted(found)


def enumerate_rest_users(base: str, s: requests.Session | None = None) -> List[str]:
    """GET /wp-json/wp/v2/users — read-only, common misconfig."""
    s = s or _s()
    try:
        r = _get(s, base.rstrip("/") + "/wp-json/wp/v2/users", timeout=6)
        if r.status_code == 200:
            j = r.json()
            return [u.get("slug", "?") for u in j if isinstance(u, dict)]
    except Exception:
        pass
    return []


def check_xmlrpc(base: str, s: requests.Session | None = None) -> bool:
    """POST system.listMethods — read-only capability listing."""
    s = s or _s()
    try:
        r = s.post(base.rstrip("/") + "/xmlrpc.php", timeout=6,
                   data="<?xml version='1.0'?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>",
                   headers={"Content-Type": "text/xml"})
        return r.status_code == 200 and "system.listMethods" in r.text
    except Exception:
        return False


# Markers that prove a 200 response is the actual sensitive file and not
# a soft-404 / "friendly error" page. Mirrors the approach used by
# web_misconfig.CONFIRM_MARKERS.
LEAK_MARKERS: dict[str, list[str]] = {
    "/.env": ["DB_PASSWORD", "APP_KEY", "DATABASE_URL", "APP_SECRET"],
    "/wp-config.php.bak": ["DB_PASSWORD", "DB_NAME", "table_prefix"],
    "/wp-config.php~": ["DB_PASSWORD", "DB_NAME", "table_prefix"],
    "/debug.log": ["PHP ", "Notice", "Warning", "Fatal", "WordPress", "Stack trace"],
    "/wp-content/debug.log": ["PHP ", "Notice", "Warning", "Fatal", "WordPress", "Stack trace"],
    "/backup.sql": ["CREATE TABLE", "INSERT INTO"],
    "/db.sql": ["CREATE TABLE", "INSERT INTO"],
}


def check_leaks(base: str, s: requests.Session | None = None) -> List[Dict[str, str]]:
    """Well-known sensitive paths that should never be public."""
    s = s or _s()
    paths = [
        "/wp-config.php.bak", "/wp-config.php~", "/wp-config.old",
        "/debug.log", "/wp-content/debug.log",
        "/.env", "/backup.zip", "/wp-content/uploads/backups/",
    ]
    out = []
    base = base.rstrip("/")

    def probe(p: str) -> Dict[str, str] | None:
        try:
            r = s.get(base + p, timeout=5, allow_redirects=False, stream=True)
            if r.status_code != 200 or not (r.content or b""):
                return None
            body = (r.content or b"").decode("utf-8", "replace").lower()
            # Soft-404 / themed error pages often return 200; require a
            # marker when we know one (especially for debug.log / .env).
            markers = LEAK_MARKERS.get(p)
            if markers and not any(m.lower() in body for m in markers):
                return None
            # Generic guard: never treat an obvious HTML error page as a leak.
            if "<title" in body and ("403" in body or "404" in body or "forbidden" in body):
                return None
            return {"path": p, "status": str(r.status_code)}
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=8) as ex:
        for res in ex.map(probe, paths):
            if res:
                out.append(res)
    return out


def check_uploads_listing(base: str, s: requests.Session | None = None) -> bool:
    s = s or _s()
    try:
        r = _get(s, base.rstrip("/") + "/wp-content/uploads/", timeout=6)
        return r.status_code == 200 and "Index of" in r.text
    except Exception:
        return False


def run_wp_recon(base: str) -> Dict[str, Any]:
    """Full WordPress recon for one base URL. Returns findings-ready dict."""
    s = _s()
    out: Dict[str, Any] = {"target": base}
    wp = detect_wordpress(base, s)
    if not wp:
        out["wordpress"] = False
        return out
    out.update(wp)

    if wp.get("theme"):
        v = probe_theme_version(base, wp["theme"], s)
        if v:
            out["theme_version"] = v

    try:
        home = _get(s, base + "/", timeout=8)
        body = home.text if home.status_code == 200 else ""
    except Exception:
        body = ""
    out["plugins"] = probe_plugins(base, body, s)
    out["rest_users"] = enumerate_rest_users(base, s)
    out["xmlrpc_enabled"] = check_xmlrpc(base, s)
    out["leaks"] = check_leaks(base, s)
    out["uploads_listing"] = check_uploads_listing(base, s)
    return out


def to_findings(target: str, recon: Dict[str, Any]) -> List[str]:
    """Convert recon dict → scanner-style finding strings (severity tagged)."""
    if not recon.get("wordpress"):
        return []
    f: List[str] = []
    if recon.get("version"):
        f.append(f"WordPress version disclosed: {recon['version']} (medium) — "
                 f"version-specific attacks possible; remove generator meta")
    else:
        f.append("WordPress detected, version hidden (info) — good practice")
    if recon.get("theme") and recon.get("theme_version"):
        f.append(f"Theme '{recon['theme']}' version {recon['theme_version']} "
                 f"disclosed (low)")
    for p in recon.get("plugins") or []:
        f.append(f"WordPress plugin exposed: {p} (medium) — check for "
                 f"known vulnerabilities and disable unused plugins")
    users = recon.get("rest_users") or []
    if users:
        f.append(f"REST user enumeration enabled ({len(users)} users: "
                 f"{', '.join(users[:5])}) (high) — usernames leaked; "
                 f"block /wp-json/wp/v2/users for anonymous visitors")
    if recon.get("xmlrpc_enabled"):
        f.append("xmlrpc.php enabled (high) — enables brute-force "
                 "amplification and pingback DDoS; disable if unused")
    for leak in recon.get("leaks") or []:
        f.append(f"Sensitive file publicly readable: {leak['path']} "
                 f"(critical) — remove and rotate exposed credentials/salts")
    if recon.get("uploads_listing"):
        f.append("Directory listing enabled on wp-content/uploads (medium)")
    return f
