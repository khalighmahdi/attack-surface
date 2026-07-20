"""
modules/finding_normalizer.py
==============================
Normalize raw finding descriptions (or events) into a standard key.

Used by:
    - Runner (header_audit issues -> finding keys)
    - payload_intelligence (finding keys -> PoC payloads)
    - risk_scoring (finding keys -> base weights)

NOTE: This module previously returned a string and was used incorrectly
by the runner (which expected a dict). It's been refactored to be a
pure function that returns a finding key, or None if unknown.
"""

from __future__ import annotations

from typing import Optional


# Keyword -> normalized finding key
_HEADER_KEYWORDS = {
    "content-security-policy": "MISSING_CSP",
    "csp": "MISSING_CSP",
    "strict-transport-security": "MISSING_HSTS",
    "hsts": "MISSING_HSTS",
    "x-frame-options": "MISSING_X_FRAME_OPTIONS",
    "x-content-type-options": "MISSING_X_CONTENT_TYPE_OPTIONS",
    "nosniff": "MISSING_X_CONTENT_TYPE_OPTIONS",
    "referrer-policy": "MISSING_REFERRER_POLICY",
    "httponly": "COOKIE_HTTPONLY_MISSING",
    "secure flag": "COOKIE_SECURE_MISSING",
    "secure cookie": "COOKIE_SECURE_MISSING",
}


def normalize_finding(description) -> Optional[str]:
    """
    Map a free-form description (or an event dict) to a finding key.

    Backward compatible: still accepts a string and returns a key.
    """
    if description is None:
        return None

    # If passed a dict, pull 'description' / 'type' / 'name'
    if isinstance(description, dict):
        haystack = " ".join(
            str(v) for v in description.values() if v is not None
        ).lower()
    else:
        haystack = str(description).lower()

    for needle, key in _HEADER_KEYWORDS.items():
        if needle in haystack:
            return key

    return None


def normalize_event(event: dict) -> Optional[dict]:
    """
    Normalize a raw event dict into a standard finding event.
    Returns the event with a `finding_key` field added (or None if not
    a recognized finding).
    """
    if not isinstance(event, dict):
        return None

    key = normalize_finding(event)
    if key is None and event.get("type"):
        # Already has a type — use it as the key if it matches the
        # FINDING_WEIGHTS vocabulary in risk_scoring
        key = event["type"]

    if key is None:
        return None

    out = dict(event)
    out["finding_key"] = key
    return out
