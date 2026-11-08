"""
modules/telemetry.py
=====================
Blue-Team: turn scan findings into SOC-ready artifacts.

1. CEF export   — Common Event Format lines for ArcSight/Splunk/QRadar
2. Syslog emit  — RFC5424 UDP syslog (rsyslog/SIEM collectors)
3. Webhook push — JSON POST to Slack-compatible / generic webhook
4. Telegram alert — direct message via Bot API (blue-team on-call phone)

All transports are optional & fail-soft: a dead webhook never breaks a scan.
"""
from __future__ import annotations

import json
import logging
import socket
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AttackSurface.Telemetry")


# --------------------------------------------------------------------------
# CEF (Common Event Format)
# --------------------------------------------------------------------------
_SEV_MAP = {"info": 1, "low": 3, "medium": 5, "high": 7, "critical": 9}

EVENT_NAMES = {
    "OPEN_PORT": "Open network port detected",
    "MISSING_HSTS": "Missing HSTS header",
    "MISSING_CSP": "Missing CSP header",
    "MISSING_X_FRAME_OPTIONS": "Missing X-Frame-Options",
    "MISSING_X_CONTENT_TYPE_OPTIONS": "Missing X-Content-Type-Options",
    "MISSING_REFERRER_POLICY": "Missing Referrer-Policy",
    "ADMIN_PANEL_EXPOSED": "Exposed admin panel",
    "PRIMARY_ADMIN_PANEL": "Primary control panel discovered",
    "SETUP_PAGE_EXPOSED": "CMS setup page exposed — takeover possible",
    "ORIGIN_IP": "Origin IP candidate identified",
}


def to_cef(event: Dict[str, Any], product: str = "AttackSurfaceScanner") -> str:
    sev = _SEV_MAP.get(str(event.get("severity", "low")).lower(), 3)
    name = EVENT_NAMES.get(event.get("type"), str(event.get("type", "event")))
    parts = []
    for k, v in event.items():
        if k in ("type", "severity") or v is None:
            continue
        safe_v = str(v).replace(" ", "\\ ")
        parts.append(f"{k}={safe_v}")
    fields = " ".join(parts)
    return (f"CEF:0|MahdiK|{product}|0.8|{event.get('type','EVENT')}|"
            f"{name}|{sev}|{fields}")


# --------------------------------------------------------------------------
# Syslog (UDP, RFC5424-ish)
# --------------------------------------------------------------------------
def send_syslog(events: List[Dict[str, Any]], host: str, port: int = 514) -> int:
    sent = 0
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        for ev in events:
            msg = to_cef(ev)
            data = f"<134>1 - scanner {msg}".encode("utf-8", "ignore")[:1400]
            sock.sendto(data, (host, port))
            sent += 1
        sock.close()
    except Exception as e:
        logger.warning("syslog send failed: %s", e)
    return sent


# --------------------------------------------------------------------------
# Webhook (Slack-compatible or generic JSON)
# --------------------------------------------------------------------------
def push_webhook(events: List[Dict[str, Any]], url: str,
                 only: tuple = ("high", "critical")) -> int:
    if not url:
        return 0
    import requests
    sent = 0
    interesting = [e for e in events
                   if str(e.get("severity", "")).lower() in only]
    if not interesting:
        return 0
    lines = []
    for ev in interesting[:20]:
        icon = "🔴" if ev.get("severity") == "critical" else "🟠"
        lines.append(f"{icon} *{ev.get('type')}* on `{ev.get('domain')}` "
                     f"({ev.get('severity')})")
    payload = {"text": "🛡 Attack-Surface alerts:\n" + "\n".join(lines)}
    try:
        requests.post(url, json=payload, timeout=8)
        sent = len(interesting)
    except Exception as e:
        logger.warning("webhook push failed: %s", e)
    return sent


# --------------------------------------------------------------------------
# Telegram (blue-team on-call)
# --------------------------------------------------------------------------
def push_telegram(events: List[Dict[str, Any]], bot_token: str,
                  chat_id: str, only: tuple = ("high", "critical")) -> int:
    if not bot_token or not chat_id:
        return 0
    import requests
    interesting = [e for e in events
                   if str(e.get("severity", "")).lower() in only]
    if not interesting:
        return 0
    lines = []
    for ev in interesting[:20]:
        icon = "🚨" if ev.get("severity") == "critical" else "⚠️"
        lines.append(f"{icon} {ev.get('type')} — {ev.get('domain')} ({ev.get('severity')})")
    text = "🛡 <b>Attack-Surface Alert</b>\n" + "\n".join(lines)
    try:
        requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json={"chat_id": chat_id, "text": text, "parse_mode": "HTML"},
            timeout=8,
        )
        return len(interesting)
    except Exception as e:
        logger.warning("telegram push failed: %s", e)
        return 0
