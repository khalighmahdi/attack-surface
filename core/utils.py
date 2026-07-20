"""
core/utils.py
==============
Small utilities shared across modules.
"""

from __future__ import annotations

import re


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)"  # must not start with hyphen
    r"[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+"  # labels
    r"(?<!-)$",  # must not end with hyphen
    re.IGNORECASE,
)


def sanitize_domain(domain: str) -> str:
    """
    Normalize a user-supplied domain string:
        - strip whitespace
        - lowercase
        - remove scheme (http://, https://)
        - remove path/query/fragment
        - remove trailing dot

    Raises ValueError if the result doesn't look like a valid domain.
    """
    if not domain or not isinstance(domain, str):
        raise ValueError("Domain must be a non-empty string")

    d = domain.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0]
    d = d.split("?")[0]
    d = d.split("#")[0]
    d = d.rstrip(".")

    if not _DOMAIN_RE.match(d):
        raise ValueError(f"Invalid domain: {domain!r}")

    return d
