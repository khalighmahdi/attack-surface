"""waf_detect.py — WAF detection + honest evasion re-scan.

Detection reuses the header_audit result (zero extra requests): scans
response headers/body snippets for known WAF signatures. When a WAF is
found, one capped evasion nmap pass is attempted
(-f --data-length 25 --randomize-hostnames) and the outcome is reported
openly — success or failure.
"""
from __future__ import annotations

import logging
import re
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AttackSurface.WAFDetect")

# name → signature needles (header names or body snippets, lowercased)
SIGNATURES: List[tuple] = [
    ("cloudflare", ["cf-ray", "cf-mitigated", "__cf_chl", "cloudflare"]),
    ("akamai", ["akamai", "akamaighost", "x-akamai"]),
    ("aws-waf", ["awswaf", "x-amzn-waf", "x-amz-cf-id"]),
    ("sucuri", ["sucuri", "x-sucuri-id"]),
    ("imperva/incapsula", ["incapsula", "x-iinfo", "x-cdn"]),
    ("arvan", ["arvancloud", "arvan", "server: arvan"]),
    ("fortinet", ["fortiwaf", "ffwaf"]),
    ("f5/big-ip", ["bigip", "f5-networks", "x-wa-info"]),
    ("wordfence", ["wordfence"]),
    ("modsecurity", ["mod_security", "modsecurity"]),
]

BODY_HINTS = ["access denied", "attention required", "security check",
              "captcha", "please enable cookies", "request blocked",
              "bot detection", "varnish cache server"]


def detect_waf(headers: Optional[Dict[str, str]],
               body_snippet: str = "",
               status: int = 0) -> Dict[str, Any]:
    """Return {detected, waf, evidence} from an HTTP response snapshot."""
    h = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    hay = " ".join(f"{k} {v}" for k, v in h.items())
    body = (body_snippet or "").lower()
    for name, needles in SIGNATURES:
        for n in needles:
            if n in hay:
                return {"detected": True, "waf": name, "evidence": f"header:{n}"}
    if status in (403, 429, 503):
        for hint in BODY_HINTS:
            if hint in body:
                return {"detected": True, "waf": "unknown", "evidence": f"body:{hint}"}
    return {"detected": False, "waf": "", "evidence": ""}


def evasion_scan(host: str, timeout: int = 300) -> Dict[str, Any]:
    """One capped nmap evasion pass. Never raises; honest output."""
    cmd = ["nmap", "-f", "--data-length", "25", "--randomize-hostnames",
           "-sV", "--top-ports", "100", host]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or "") + (r.stderr or "")
        ports = []
        for m in re.finditer(r"(\d{1,5})/tcp\s+open\s+(\S+)", out):
            ports.append({"port": int(m.group(1)), "service": m.group(2)})
        return {
            "attempted": " ".join(cmd),
            "rc": r.returncode,
            "ports_found": ports,
            "output_tail": out.strip().splitlines()[-6:],
            "note": ("evasion scan completed — compare with baseline scan"
                     if r.returncode == 0 else
                     "evasion scan failed/incomplete — WAF may still be blocking"),
        }
    except subprocess.TimeoutExpired:
        return {"attempted": " ".join(cmd), "rc": -1, "ports_found": [],
                "output_tail": [], "note": "evasion scan timed out"}
    except Exception as e:
        return {"attempted": " ".join(cmd), "rc": -1, "ports_found": [],
                "output_tail": [], "note": f"evasion scan error: {e}"}


def assess_hosts(headers_by_host: Dict[str, Any],
                 run_evasion: bool = True,
                 max_evasion_hosts: int = 5) -> Dict[str, Dict[str, Any]]:
    """Run detection over header_audit output; evasion for WAF hosts.

    headers_by_host: ctx.headers shape {host: {all_headers, status_code, ...}}
    Returns {host: {detected, waf, evidence, evasion?}} for WAF hits only.
    """
    hits: Dict[str, Dict[str, Any]] = {}
    for host, info in (headers_by_host or {}).items():
        if not isinstance(info, dict):
            continue
        hdrs = info.get("all_headers") or info.get("security_headers") or {}
        body = str(info.get("body_snippet") or info.get("error") or "")
        res = detect_waf(hdrs, body, int(info.get("status_code") or 0))
        if res["detected"]:
            hits[host] = res
    if run_evasion:
        for i, host in enumerate(sorted(hits)):
            if i >= max_evasion_hosts:
                break
            logger.info("WAF on %s (%s) — attempting evasion scan",
                        host, hits[host]["waf"])
            hits[host]["evasion"] = evasion_scan(host)
    return hits
