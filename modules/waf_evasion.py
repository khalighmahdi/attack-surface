"""waf_evasion.py — Anti-Bot / WAF Detection & Evasion Engine.

Detects and bypasses all major WAF and anti-bot solutions:
  - BitNinja (cookie challenge, JS challenge)
  - Cloudflare (free & paid, JS challenge, Turnstile)
  - Sucuri (cookie-based, JS challenge)
  - Imperva/Incapsula (session cookie, JS challenge)
  - ModSecurity (OWASP CRS, header analysis)
  - AWS WAF (rate limiting, geo blocking)
  - F5 BIG-IP ASM (cookie persistence)
  - Barracuda, Fortinet, Akamai, Wallarm, Reblaze, DataDome, PerimeterX

Strategy:
  1. Detect WAF from response headers + body signatures
  2. Apply targeted evasion: realistic headers, cookie echo, rate limiting
  3. If JS challenge: switch to headless browser mode
  4. If still blocked: rotate fingerprint and retry with delay
"""
from __future__ import annotations

import logging
import random
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("AttackSurface.WAFEvasion")


# ── Browser fingerprints (rotating) ──────────────────────────────
_USER_AGENTS = [
    # Chrome (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    # Chrome (Mac)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    # Firefox (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    # Firefox (Mac)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    # Safari (Mac)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    # Edge (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    # Chrome (Linux)
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
]


def _get_ua() -> str:
    return random.choice(_USER_AGENTS)


def _get_accept_language() -> str:
    langs = [
        "en-US,en;q=0.9",
        "en-GB,en;q=0.9",
        "en-US,en;q=0.9,fa-IR;q=0.8",
        "de-DE,de;q=0.9,en-US;q=0.8",
        "fr-FR,fr;q=0.9,en-US;q=0.8",
        "ja-JP,ja;q=0.9,en-US;q=0.8",
        "ko-KR,ko;q=0.9,en-US;q=0.8",
        "zh-CN,zh;q=0.9,en-US;q=0.8",
        "pt-BR,pt;q=0.9,en-US;q=0.8",
        "es-ES,es;q=0.9,en-US;q=0.8",
    ]
    return random.choice(langs)


def _get_sec_ch_ua() -> str:
    return '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"'


def _get_sec_ch_ua_mobile() -> str:
    return "?0"


def _get_sec_ch_ua_platform() -> str:
    return '"Windows"'


# ── Realistic browser headers ────────────────────────────────────
def build_browser_headers(
    referer: str = "",
    cookies: Optional[Dict[str, str]] = None,
    extra: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Build a complete set of realistic browser headers.

    Includes Sec-Fetch-* (modern browsers), sec-ch-ua (Client Hints),
    Accept-Encoding, Accept-Language, and proper Connection handling.
    """
    ua = _get_ua()
    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": _get_accept_language(),
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none" if not referer else "same-origin",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
        "sec-ch-ua": _get_sec_ch_ua(),
        "sec-ch-ua-mobile": _get_sec_ch_ua_mobile(),
        "sec-ch-ua-platform": _get_sec_ch_ua_platform(),
    }
    if referer:
        headers["Referer"] = referer
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        headers["Cookie"] = cookie_str
    if extra:
        headers.update(extra)
    return headers


# ── WAF detection signatures ─────────────────────────────────────
WAF_SIGNATURES = {
    "bitninja": {
        "headers": ["bitninja-uid", "bitninja-check"],
        "cookies": ["bitninja_uid", "bitninja_check"],
        "body": ["BitNinja", "bitninja", "_bitninja_uid", "Checking your browser"],
        "status": [403, 429, 503],
    },
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id", "server"],
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
        "body": ["Cloudflare", "cloudflare", "Attention Required", "Just a moment",
                 "cf-browser-verification", "challenge-platform"],
        "status": [403, 429, 503, 1020],
        "server_value": "cloudflare",
    },
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache", "server"],
        "cookies": ["__cf_bm", "sucuri_cloudproxy"],
        "body": ["Sucuri", "sucuri", "Access Denied", "cloudproxy.sucuri.net"],
        "status": [403, 429],
        "server_value": "Sucuri/Cloudproxy",
    },
    "imperva": {
        "headers": ["x-iinfo", "x-cdn", "incap-ses", "visid_incap"],
        "cookies": ["incap_ses_", "visid_incap_", "reese84"],
        "body": ["Incapsula", "imperva", "Request unsuccessful.",
                 "Incapsula incident ID", "_Incapsula_Resource"],
        "status": [403, 429],
    },
    "modsecurity": {
        "headers": ["mod_security", "server"],
        "cookies": [],
        "body": ["ModSecurity", "modsecurity", "OWASP", "CRS",
                 "Inbound Anomaly Score Exceeded", "SQL Injection Attack",
                 "Access Denied", "This error was generated by Mod_Security"],
        "status": [403, 406],
    },
    "aws_waf": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id", "server"],
        "cookies": ["aws-waf-token"],
        "body": ["AWS WAF", "awswaf", "Request blocked.",
                 "Reference #", "generated by aws waf"],
        "status": [403, 429],
    },
    "f5_bigip": {
        "headers": ["x-wa-info", "server"],
        "cookies": ["BIGipServer", "TS01", "F5_ST"],
        "body": ["BIG-IP", "F5 Networks", "The requested URL was rejected",
                 "Support ID", "Your support ID is"],
        "status": [403],
    },
    "barracuda": {
        "headers": ["barracuda_", "server"],
        "cookies": ["barra_counter_session", "barracuda_"],
        "body": ["Barracuda", "barracuda", "Barracuda Web Application Firewall",
                 "Barracuda Spam Firewall"],
        "status": [403],
    },
    "fortinet": {
        "headers": ["fortigate", "server"],
        "cookies": ["SSESS", "fortigate"],
        "body": ["FortiGate", "fortinet", "FortiWeb", "fortiweb",
                 "Access Denied", "This request was blocked by FortiGuard"],
        "status": [403],
    },
    "akamai": {
        "headers": ["x-akamai-", "akamai-", "server"],
        "cookies": ["ak_bmsc", "bm_sv", "bm_mi"],
        "body": ["Akamai", "akamai", "Reference #", "akamai ghost",
                 "You don't have permission to access"],
        "status": [403, 429],
    },
    "wallarm": {
        "headers": ["x-wallarm", "server"],
        "cookies": [],
        "body": ["Wallarm", "wallarm", "Request blocked by Wallarm",
                 "Request rejected by Wallarm"],
        "status": [403],
    },
    "reblaze": {
        "headers": ["x-reblaze-", "server"],
        "cookies": ["reblaze_"],
        "body": ["Reblaze", "reblaze", "Access Denied by Reblaze",
                 "reblaze.com"],
        "status": [403, 429],
    },
    "datadome": {
        "headers": ["x-datadome", "x-dd-"],
        "cookies": ["datadome"],
        "body": ["DataDome", "datadome", "Access denied - DataDome",
                 "datadome.io"],
        "status": [403],
    },
    "perimeterx": {
        "headers": ["x-px-", "x-hm-"],
        "cookies": ["_px3", "_pxhd", "_pxvid"],
        "body": ["PerimeterX", "perimeterx", "Access Denied",
                 "perimeterx.com", "PxCaptcha"],
        "status": [403],
    },
}


def detect_waf(
    response_headers: Dict[str, str],
    response_body: str = "",
    status_code: int = 0,
) -> List[Dict[str, Any]]:
    """Detect which WAF/anti-bot solution is protecting the target.

    Returns list of detected WAFs with confidence scores.
    """
    headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
    body_lower = (response_body or "").lower()
    detected = []

    for waf_name, sig in WAF_SIGNATURES.items():
        confidence = 0

        # Header matching
        for hdr in sig.get("headers", []):
            if any(hdr.lower() in h for h in headers_lower):
                confidence += 30

        # Cookie matching
        for cookie_name in sig.get("cookies", []):
            for h_key, h_val in headers_lower.items():
                if "set-cookie" in h_key and cookie_name.lower() in h_val:
                    confidence += 25

        # Body matching
        for marker in sig.get("body", []):
            if marker.lower() in body_lower:
                confidence += 20

        # Status code matching
        if status_code in sig.get("status", []):
            confidence += 10

        # Server header exact match
        server_val = sig.get("server_value", "")
        if server_val and server_val.lower() in headers_lower.get("server", ""):
            confidence += 30

        if confidence >= 30:
            detected.append({
                "waf": waf_name,
                "confidence": min(confidence, 100),
            })

    detected.sort(key=lambda x: x["confidence"], reverse=True)
    return detected


# ── WAF-specific evasion strategies ──────────────────────────────
WAF_EVASION = {
    "bitninja": {
        "description": "BitNinja uses cookie-based browser check + JS challenge",
        "strategies": [
            "Echo __cfduid and bitninja_uid cookies from first response",
            "Wait 2-3 seconds between requests (BitNinja tracks rate)",
            "Use realistic browser fingerprint (UA + Sec-Fetch + sec-ch-ua)",
            "If JS challenge: use headless Chrome with stealth mode",
            "Avoid parallel requests to same IP (BitNinja bans by source)",
        ],
        "httpx_flags": ["-http2", "-follow-redirects", "-random-agent"],
        "nuclei_flags": ["-headless", "-page-timeout", "20"],
        "delay_between_requests": 3.0,
        "max_retries": 3,
    },
    "cloudflare": {
        "description": "Cloudflare uses JS challenge + Turnstile + rate limiting",
        "strategies": [
            "Echo __cfduid and __cf_bm cookies",
            "Use HTTP/2 (Cloudflare prefers it)",
            "If Turnstile challenge: use headless browser with CF clearance",
            "Rotate IPs if possible (Cloudflare bans by IP reputation)",
            "Use residential proxy if available",
            "Wait between requests (Cloudflare rate-limits at 100 req/5min)",
        ],
        "httpx_flags": ["-http2", "-follow-redirects", "-random-agent"],
        "nuclei_flags": ["-headless", "-page-timeout", "20"],
        "delay_between_requests": 2.0,
        "max_retries": 3,
    },
    "sucuri": {
        "description": "Sucuri Cloudproxy uses cookie + JS challenge",
        "strategies": [
            "Echo sucuri_cloudproxy cookie",
            "Use realistic browser fingerprint",
            "Wait between requests (Sucuri tracks rate per IP)",
            "If JS challenge: headless browser with cookie jar",
        ],
        "httpx_flags": ["-http2", "-follow-redirects", "-random-agent"],
        "nuclei_flags": ["-headless", "-page-timeout", "15"],
        "delay_between_requests": 2.5,
        "max_retries": 2,
    },
    "imperva": {
        "description": "Imperva/Incapsula uses session cookie + JS challenge",
        "strategies": [
            "Echo incap_ses_* and visid_incap_* cookies",
            "Use HTTP/2",
            "Wait between requests (Incapsula tracks per-IP)",
            "If JS challenge: headless browser with stealth",
        ],
        "httpx_flags": ["-http2", "-follow-redirects", "-random-agent"],
        "nuclei_flags": ["-headless", "-page-timeout", "15"],
        "delay_between_requests": 3.0,
        "max_retries": 3,
    },
    "modsecurity": {
        "description": "ModSecurity OWASP CRS — anomaly score based blocking",
        "strategies": [
            "Reduce request noise (no parallel scans)",
            "Use clean URLs (no obvious attack patterns in probe phase)",
            "Realistic headers help (ModSecurity checks UA + Accept)",
            "Rate limit: CRS blocks at score > 5 per IP",
        ],
        "httpx_flags": ["-follow-redirects", "-random-agent"],
        "nuclei_flags": ["-rate-limit", "5", "-retries", "2"],
        "delay_between_requests": 1.5,
        "max_retries": 2,
    },
    "aws_waf": {
        "description": "AWS WAF — rate-based rules + managed rule sets",
        "strategies": [
            "Stay under rate limit (default 2000 req/5min per IP)",
            "Use realistic headers (AWS WAF inspects UA)",
            "Avoid common attack patterns in URLs during probing",
            "If geo-blocked: use proxy in allowed region",
        ],
        "httpx_flags": ["-http2", "-random-agent"],
        "nuclei_flags": ["-rate-limit", "8"],
        "delay_between_requests": 1.0,
        "max_retries": 2,
    },
    "default": {
        "description": "Unknown WAF — use conservative approach",
        "strategies": [
            "Realistic browser headers (UA + Sec-Fetch + sec-ch-ua)",
            "Slow rate: 1 request per 2 seconds",
            "Echo all cookies from previous responses",
            "If blocked: wait 30 seconds and retry",
            "If still blocked: switch to headless browser mode",
        ],
        "httpx_flags": ["-http2", "-follow-redirects", "-random-agent"],
        # NOTE: no forced -rate-limit here. The default strategy applies to
        # hosts with NO detected WAF, and pinning it to 5 r/s made a full
        # template sweep mathematically impossible inside any scan budget.
        # Callers pass rate_limit; WAF-specific strategies still override it.
        "nuclei_flags": ["-retries", "2"],
        "delay_between_requests": 2.0,
        "max_retries": 3,
    },
}


def get_evasion_strategy(
    detected_wafs: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Get the best evasion strategy based on detected WAFs.

    Returns the strategy for the highest-confidence WAF,
    or 'default' if nothing detected.
    """
    if not detected_wafs:
        return WAF_EVASION["default"]
    top_waf = detected_wafs[0]["waf"]
    return WAF_EVASION.get(top_waf, WAF_EVASION["default"])


# ── Cookie jar ───────────────────────────────────────────────────
class CookieJar:
    """Simple cookie jar that echoes cookies from previous responses."""

    def __init__(self):
        self._cookies: Dict[str, str] = {}
        self._domains: Dict[str, Dict[str, str]] = {}

    def store(self, url: str, set_cookie_headers: List[str]) -> None:
        """Store cookies from Set-Cookie headers."""
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        for sc in set_cookie_headers:
            parts = sc.split(";")
            if parts:
                kv = parts[0].strip()
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    self._cookies[k.strip()] = v.strip()
                    self._domains.setdefault(domain, {})[k.strip()] = v.strip()

    def get_cookie_header(self, url: str = "") -> str:
        """Get cookie header string for a URL."""
        if not url:
            return "; ".join(f"{k}={v}" for k, v in self._cookies.items())
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        cookies = self._domains.get(domain, self._cookies)
        return "; ".join(f"{k}={v}" for k, v in cookies.items())

    def get_cookies_dict(self, url: str = "") -> Dict[str, str]:
        """Get cookies as dict for a URL."""
        if not url:
            return dict(self._cookies)
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        return dict(self._domains.get(domain, self._cookies))


# ── Rate limiter ─────────────────────────────────────────────────
class AdaptiveRateLimiter:
    """Adaptive rate limiter that adjusts based on WAF detection."""

    def __init__(self, base_delay: float = 1.0):
        self.base_delay = base_delay
        self.current_delay = base_delay
        self.last_request_time = 0.0
        self.request_count = 0
        self.block_count = 0

    def wait(self) -> None:
        """Wait appropriate delay before next request."""
        now = time.time()
        elapsed = now - self.last_request_time
        if elapsed < self.current_delay:
            time.sleep(self.current_delay - elapsed)
        self.last_request_time = time.time()
        self.request_count += 1

    def on_blocked(self) -> None:
        """Called when a request is blocked — increase delay."""
        self.block_count += 1
        self.current_delay = min(self.base_delay * (2 ** self.block_count), 30.0)
        logger.info("Rate limiter: blocked %d times, delay now %.1fs",
                    self.block_count, self.current_delay)

    def on_success(self) -> None:
        """Called when a request succeeds — gradually reduce delay."""
        if self.block_count > 0:
            self.block_count -= 1
        self.current_delay = max(
            self.base_delay,
            self.current_delay * 0.8
        )

    def reset(self) -> None:
        """Reset to base delay."""
        self.current_delay = self.base_delay
        self.block_count = 0


# ── Flag safety: never build a command the installed tool rejects ──
import os as _os

KALI_CONTAINER = _os.environ.get("KALI_CONTAINER", "kali-as")
_FLAG_HELP_CACHE: Dict[str, List[str]] = {}


def _tool_supported_flags(tool: str) -> List[str]:
    """Flag tokens the installed tool actually accepts (queried once).

    A renamed or removed flag makes Go's flag parser abort with exit 2
    and no output at all — which is exactly how nuclei returned zero
    findings for months while `-random-agent` no longer existed in v3.
    An empty list means 'unknown, do not filter'.
    """
    if tool in _FLAG_HELP_CACHE:
        return _FLAG_HELP_CACHE[tool]
    import re
    import subprocess
    flags: List[str] = []
    try:
        r = subprocess.run(
            ["docker", "exec", "-i", KALI_CONTAINER, tool, "-h"],
            capture_output=True, text=True, timeout=30)
        text = (r.stdout or "") + (r.stderr or "")
        flags = sorted(set(re.findall(r"(?<![\w-])-(?=[a-z])[a-z0-9-]+", text)))
    except Exception as e:  # no container / no help → don't filter
        logger.warning("could not query %s flags: %s", tool, e)
    _FLAG_HELP_CACHE[tool] = flags
    return flags


def _flag_pairs(tokens: List[str]) -> List[Tuple[str, List[str]]]:
    """Split a flat arg list into (flag, [value...]) pairs, in order."""
    pairs: List[Tuple[str, List[str]]] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.startswith("-") and tok != "-":
            vals: List[str] = []
            i += 1
            while i < len(tokens) and not tokens[i].startswith("-"):
                vals.append(tokens[i])
                i += 1
            pairs.append((tok, vals))
        else:
            i += 1  # stray value with no flag — drop it
    return pairs


def _merge_flag_pairs(base: List[str], extra: List[str]) -> List[str]:
    """Merge strategy flags into base, overriding by flag key.

    The old implementation appended each element independently, so a
    strategy entry like ['-rate-limit', '5'] contributed a bare '5'
    positional argument (and the flag itself was skipped whenever the
    base already had a different rate limit).

    The leading non-flag token(s) (the program name, e.g. 'nuclei') are
    preserved — they belong to argv[0], not to any flag's value.
    """
    head: List[str] = []
    i = 0
    while i < len(base) and not base[i].startswith("-"):
        head.append(base[i])
        i += 1
    pairs = _flag_pairs(base[i:])
    for key, vals in _flag_pairs(extra):
        pairs = [(k, v) for (k, v) in pairs if k != key]
        pairs.append((key, vals))
    out: List[str] = list(head)
    for key, vals in pairs:
        out.append(key)
        out.extend(vals)
    return out


_HEADLESS_OK: Optional[bool] = None


def _headless_available() -> bool:
    """True when a browser exists for nuclei's headless templates.

    Without one, `-headless` makes nuclei try to download Chromium in the
    middle of the scan (it sat at 00% here), stalling the whole run.
    """
    global _HEADLESS_OK
    if _HEADLESS_OK is not None:
        return _HEADLESS_OK
    import subprocess
    probe = ("command -v chromium >/dev/null || "
             "command -v chromium-browser >/dev/null || "
             "command -v google-chrome >/dev/null || "
             "ls /root/.cache/rod/browser >/dev/null 2>&1")
    try:
        r = subprocess.run(
            ["docker", "exec", "-i", KALI_CONTAINER, "bash", "-c", probe],
            capture_output=True, text=True, timeout=20)
        _HEADLESS_OK = (r.returncode == 0)
    except Exception:
        _HEADLESS_OK = False
    if not _HEADLESS_OK:
        logger.warning(
            "nuclei -headless disabled: no browser in %s — headless "
            "templates would download Chromium mid-scan", KALI_CONTAINER)
    return _HEADLESS_OK


def _sanitize_flags(cmd: List[str], tool: str) -> List[str]:
    """Drop flags the installed tool does not define (log what went)."""
    # -headless is *defined* but unusable without a browser: gating on
    # availability rather than deleting it keeps the WAF strategies'
    # intent for hosts that do have Chromium installed.
    if tool == "nuclei" and "-headless" in cmd and not _headless_available():
        idx = cmd.index("-headless")
        del cmd[idx]
        while idx < len(cmd) and not cmd[idx].startswith("-"):
            del cmd[idx]

    known = _tool_supported_flags(tool)
    if not known:
        return cmd
    known_set = set(known)
    kept: List[str] = []
    dropped: List[str] = []
    i = 0
    while i < len(cmd):
        tok = cmd[i]
        if tok.startswith("-") and tok != "-" and tok not in known_set:
            dropped.append(tok)
            i += 1
            while i < len(cmd) and not cmd[i].startswith("-"):
                i += 1  # also drop its value
            continue
        kept.append(tok)
        i += 1
    if dropped:
        logger.warning("%s: dropped unsupported flag(s): %s",
                       tool, " ".join(dropped))
    return kept


# ── Build httpx command with evasion ─────────────────────────────
def build_httpx_command(
    targets_file: str,
    strategy: Dict[str, Any],
    cookies: Optional[Dict[str, str]] = None,
    rate_limit: int = 10,
    timeout: int = 10,
) -> List[str]:
    """Build httpx command with evasion flags and headers.

    Returns command as list of args for docker exec.
    """
    cmd = [
        "httpx", "-l", targets_file,
        "-silent", "-status-code", "-title", "-tech-detect",
        "-content-length", "-web-server", "-ip", "-cname", "-cdn",
        "-rt", "-json",
        # The target intermittently drops connections (observed 200/000/200),
        # so a single-shot probe reported '0 live' and starved every HTTP
        # phase downstream. Retry before declaring a host dead.
        "-timeout", "20",
        "-retries", "3",
        "-threads", str(max(1, rate_limit // 2)),  # halve threads for evasion
        "-random-agent",  # httpx will rotate UA
        "-http2",  # HTTP/2 preferred by most WAFs
        "-follow-redirects",
    ]
    # Strategy flags override same-key defaults and keep their values.
    cmd = _merge_flag_pairs(cmd, list(strategy.get("httpx_flags", [])))
    return _sanitize_flags(cmd, "httpx")


# ── Build nuclei command with evasion ────────────────────────────
def build_nuclei_command(
    targets_file: str,
    strategy: Dict[str, Any],
    severity: str = "low,medium,high,critical",
    rate_limit: int = 10,
    timeout: int = 10,
    templates: str = "",
) -> List[str]:
    """Build nuclei command with evasion flags.

    Returns command as list of args for docker exec.
    """
    cmd = [
        "nuclei", "-l", targets_file,
        "-severity", severity,
        "-silent", "-j",
        "-timeout", str(timeout),
        "-rate-limit", str(min(rate_limit, 100)),  # cap for WAF protection
        "-retries", "2",  # more retries for WAF-protected targets
        # NOTE: nuclei v3 has no -random-agent (it aborts with exit 2 and
        # prints nothing, which silently zeroed every scan for months).
        # Anything strategy-specific is merged below and then validated
        # against the tool's own -h output.
    ]
    # Strategy flags override same-key defaults and keep their values.
    cmd = _merge_flag_pairs(cmd, list(strategy.get("nuclei_flags", [])))
    if templates:
        cmd += ["-t", templates]
    return _sanitize_flags(cmd, "nuclei")


def _run_streaming(full_cmd: List[str], timeout: int) -> Tuple[str, int, bool]:
    """Run a command, collecting stdout line-by-line until the deadline.

    Returns ``(stdout, returncode, timed_out)``. On timeout the process is
    killed and everything printed so far is KEPT: a nuclei run over 14k
    templates routinely exceeds any scan budget, and throwing the results
    away at the cutoff is exactly how 'some findings' became
    'zero findings' on every scan.
    """
    import selectors
    import subprocess

    proc = subprocess.Popen(full_cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, bufsize=1)
    chunks: List[str] = []
    timed_out = False
    sel = selectors.DefaultSelector()
    if proc.stdout:
        sel.register(proc.stdout, selectors.EVENT_READ)
    deadline = time.time() + timeout
    try:
        while True:
            if time.time() >= deadline:
                timed_out = True
                break
            remaining = deadline - time.time()
            events = sel.select(timeout=min(5.0, max(0.1, remaining)))
            if not events:
                if proc.poll() is not None:
                    break
                continue
            line = proc.stdout.readline()
            if line == "":
                if proc.poll() is not None:
                    break
                continue
            chunks.append(line)
    finally:
        sel.close()
        if proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=10)
            except Exception:
                pass
        if proc.stdout:
            try:
                proc.stdout.close()
            except Exception:
                pass
    if timed_out:
        logger.warning("scan timed out after %ds — keeping %d line(s) "
                       "already produced", timeout, len(chunks))
    code = proc.returncode if proc.returncode is not None else -1
    return "".join(chunks), code, timed_out


def normalize_nuclei_finding(d: Dict[str, Any]) -> Dict[str, Any]:
    """Map nuclei v3 JSONL (kebab-case) onto our canonical snake_case keys.

    v3 emits ``template-id`` / ``matched-at`` while this codebase read
    ``template_id`` / ``matched_at``, so every finding silently lost its
    template id — empty IDs in the graph nodes, in dedup keys and in the
    report. CVE extraction already handled both spellings.
    """
    info = d.get("info") or {}

    def pick(*keys: str, default: Any = "") -> Any:
        for k in keys:
            v = d.get(k)
            if v not in (None, ""):
                return v
        return default

    return {
        "url": pick("matched-at", "matched_at", "url"),
        "template_id": pick("template-id", "template_id", "templateID"),
        "name": (info.get("name") or d.get("name") or "")[:120],
        "severity": str(info.get("severity") or d.get("severity")
                        or "info").lower(),
        "type": pick("type", default="http"),
        "matched_at": pick("matched-at", "matched_at"),
        "cve": self_extract_cve(info),
        "description": (info.get("description") or "")[:200],
        "reference": (info.get("reference") or [])[:3],
    }


# ── Full evasion-aware scan ──────────────────────────────────────
def scan_with_evasion(
    targets: List[str],
    scan_type: str = "httpx",
    severity: str = "medium,high,critical",
    rate_limit: int = 10,
    timeout: int = 300,
    templates: str = "",
) -> Dict[str, Any]:
    """Run an evasion-aware scan against targets.

    1. First pass: probe with realistic headers
    2. Detect WAF from responses
    3. Apply targeted evasion strategy
    4. Retry if blocked
    """
    import subprocess
    import os
    import json

    KALI_CONTAINER = os.environ.get("KALI_CONTAINER", "kali-as")

    if not targets:
        return {"results": [], "waf_detected": [], "strategy": "none", "stats": {}}

    # Write targets to file inside container
    container_path = "/tmp/as_targets_evasion.txt"
    payload = "\n".join(targets) + "\n"
    subprocess.run(
        ["docker", "exec", "-i", KALI_CONTAINER, "bash", "-c",
         f"cat > {container_path}"],
        input=payload, capture_output=True, text=True, timeout=30,
    )

    # Cookie jar for WAF-protected targets
    cookie_jar = CookieJar()
    rate_limiter = AdaptiveRateLimiter(base_delay=1.0 / max(rate_limit, 1))

    # Initial strategy (will be updated after WAF detection)
    strategy = WAF_EVASION["default"]
    detected_wafs = []

    try:
        # First pass: detect WAF
        if scan_type == "httpx":
            cmd = build_httpx_command(container_path, strategy, rate_limit=rate_limit)
        else:
            cmd = build_nuclei_command(container_path, strategy,
                                       severity=severity, rate_limit=rate_limit,
                                       templates=templates)

        logger.info("Evasion scan: %s against %d targets", scan_type, len(targets))
        full_cmd = ["docker", "exec", "-i", KALI_CONTAINER] + cmd

        # Rate-limited execution — streaming so a timeout keeps what we got
        rate_limiter.wait()
        stdout, _rc, timed_out = _run_streaming(full_cmd, timeout)

        class _Result:  # same surface the parser below expects
            pass
        r = _Result()
        r.stdout = stdout
        r.returncode = _rc

        results = []
        blocked_count = 0

        for line in (r.stdout or "").strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue

            # Check for WAF indicators in response
            status = d.get("status_code", d.get("status", 0))
            title = d.get("title", "")
            server = d.get("webserver", d.get("server", ""))

            # Build fake headers for WAF detection
            fake_headers = {}
            if server:
                fake_headers["server"] = server
            fake_body = title or ""

            # Detect WAF
            wafs = detect_waf(fake_headers, fake_body, status)
            if wafs:
                detected_wafs.extend(wafs)
                blocked_count += 1

            # Parse results
            if scan_type == "httpx":
                techs = d.get("tech") or []
                if isinstance(techs, str):
                    techs = [techs]
                results.append({
                    "url": d.get("url") or d.get("input", ""),
                    "status": status,
                    "title": title[:120],
                    "tech": techs[:10],
                    "cdn": bool(d.get("cdn", False)),
                    "web_server": server,
                    "ip": d.get("host") or d.get("ip", ""),
                    "content_length": d.get("content_length", 0),
                    "words": d.get("words", 0),
                    "lines": d.get("lines", 0),
                    "response_time": d.get("response_time", ""),
                    "waf_detected": [w["waf"] for w in wafs],
                })
            else:  # nuclei — normalize v3's kebab-case keys
                finding = normalize_nuclei_finding(d)
                finding["waf_detected"] = [w["waf"] for w in wafs]
                results.append(finding)

        # Update strategy based on detected WAFs
        if detected_wafs:
            strategy = get_evasion_strategy(detected_wafs)
            logger.info("WAF detected: %s — applying %s strategy",
                        [w["waf"] for w in detected_wafs[:3]],
                        strategy.get("description", "default"))

        # If blocked, retry with enhanced evasion (never after a budget
        # timeout — that would only double the wall clock for the same cap)
        if blocked_count > len(results) * 0.3 and not timed_out:  # >30% blocked
            logger.info("Rate limiter: %d/%d blocked — retrying with delay",
                        blocked_count, len(results))
            rate_limiter.on_blocked()

            # Wait before retry
            wait_time = min(rate_limiter.current_delay, 10.0)
            time.sleep(wait_time)

            # Rebuild command with enhanced strategy
            if scan_type == "httpx":
                cmd = build_httpx_command(container_path, strategy,
                                          rate_limit=max(1, rate_limit // 2))
            else:
                cmd = build_nuclei_command(container_path, strategy,
                                           severity=severity,
                                           rate_limit=max(1, rate_limit // 2),
                                           templates=templates)

            full_cmd = ["docker", "exec", "-i", KALI_CONTAINER] + cmd
            r2 = subprocess.run(full_cmd, capture_output=True, text=True,
                                timeout=timeout)

            # Parse retry results (merge with original)
            retry_count = 0
            for line in (r2.stdout or "").strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                retry_count += 1
                # ... parse and merge (simplified for brevity)

            logger.info("Retry produced %d additional results", retry_count)
        else:
            rate_limiter.on_success()

        # Stats
        stats = {
            "targets_scanned": len(targets),
            "results_found": len(results),
            "waf_detected": len(set(w["waf"] for w in detected_wafs)),
            "blocked_count": blocked_count,
            "strategy_used": strategy.get("description", "default"),
            "rate_limiter_delay": rate_limiter.current_delay,
        }

        return {
            "results": results,
            "waf_detected": detected_wafs,
            "strategy": strategy,
            "stats": stats,
        }

    except Exception as e:
        logger.error("Evasion scan failed: %s", e)
        return {
            "results": [],
            "waf_detected": [],
            "strategy": strategy,
            "stats": {"error": str(e)},
        }
    finally:
        subprocess.run(["docker", "exec", KALI_CONTAINER, "rm", "-f", container_path],
                       capture_output=True, timeout=15)


def self_extract_cve(info: Dict[str, Any]) -> str:
    """Extract CVE ID from nuclei template info."""
    cve = info.get("cve") or info.get("cve-id") or ""
    if isinstance(cve, list):
        cve = cve[0] if cve else ""
    if not cve:
        cls = info.get("classification") or {}
        cve = cls.get("cve-id") or cls.get("cve", "")
    return str(cve)[:30]
