"""
core/utils.py
==============
Small utilities shared across modules.
"""

from __future__ import annotations

import re

import idna


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)"  # must not start with hyphen
    r"[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+"  # labels
    r"(?<!-)$",  # must not end with hyphen
    re.IGNORECASE,
)

_HAS_NON_ASCII = re.compile(r"[^\x00-\x7F]")


def sanitize_domain(domain: str) -> str:
    """
    Normalize a user-supplied domain string:
        - strip whitespace
        - lowercase
        - remove scheme (http://, https://)
        - remove path/query/fragment
        - remove trailing dot
        - IDN unicode → punycode (any non-ASCII label → xn--; the actual
          non-ASCII inputs live in tests/test_idn.py)

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

    # Internationalized domain names (Persian/Arabic/...) → punycode
    if _HAS_NON_ASCII.search(d):
        try:
            d = idna.encode(d, uts46=True).decode("ascii")
        except idna.IDNAError as e:
            raise ValueError(f"Invalid IDN domain: {domain!r} ({e})") from e

    if not _DOMAIN_RE.match(d):
        raise ValueError(f"Invalid domain: {domain!r}")

    return d
