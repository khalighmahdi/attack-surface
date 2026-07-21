"""
core/scope.py
=============
Scope validation for authorized scanning.

In a real bug-bounty or pentest engagement, scanning assets outside
the agreed scope is illegal. This module:

  1. Loads a list of in-scope domains (suffix match) from a file or CLI.
  2. Validates every host we discover against that list.
  3. Emits a clear warning when an out-of-scope host is detected.
  4. Optionally HARD-stops when the primary target itself is out of scope.

File format (`scope.txt`):
    # Comments start with #, one entry per line
    example.com
    *.example.com
    api.example.com

A leading `*.` means "this domain and any subdomain of it".
A bare domain matches itself and all subdomains.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Set
import fnmatch


def _normalize(host: str) -> str:
    return (host or "").strip().lower().rstrip(".")


def _entry_matches_pattern(host: str, pattern: str) -> bool:
    """
    Returns True if `host` matches `pattern`. Patterns supported:
        "example.com"        -> exact OR any subdomain
        "*.example.com"      -> any subdomain (NOT the apex)
        "api.example.com"    -> exact or any subdomain (subdomain of subdomain)
    """
    h = _normalize(host)
    p = _normalize(pattern)
    if not h or not p:
        return False
    if p.startswith("*."):
        # "*.example.com" -> ".example.com" suffix on host, not equal to "example.com"
        suffix = p[1:]  # ".example.com"
        return h.endswith(suffix) and h != suffix.lstrip(".")
    # Bare / explicit domain: match apex + all subdomains
    return h == p or h.endswith("." + p)


@dataclass
class ScopeFilter:
    """
    Holds the in-scope patterns and decides whether a host is allowed.

    Modes:
        "warn"  (default) -> log a warning, keep the host
        "soft"           -> skip the host (do not scan it)
        "strict"         -> abort the scan if PRIMARY target is out of scope
    """

    primary: str
    patterns: List[str] = field(default_factory=list)
    mode: str = "warn"

    def __post_init__(self):
        self.primary = _normalize(self.primary)
        self.patterns = [_normalize(p) for p in self.patterns if p and not p.startswith("#")]
        # Always include the primary target itself, even if user forgot it
        if self.primary and self.primary not in self.patterns:
            self.patterns.append(self.primary)
        if self.mode not in ("warn", "soft", "strict"):
            raise ValueError(f"unknown scope mode: {self.mode}")

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------
    @classmethod
    def from_file(cls, primary: str, path: str, mode: str = "warn") -> "ScopeFilter":
        patterns: List[str] = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    patterns.append(line)
        except FileNotFoundError:
            pass
        return cls(primary=primary, patterns=patterns, mode=mode)

    @classmethod
    def from_list(cls, primary: str, patterns: Iterable[str], mode: str = "warn") -> "ScopeFilter":
        return cls(primary=primary, patterns=list(patterns or []), mode=mode)

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    def in_scope(self, host: str) -> bool:
        h = _normalize(host)
        if not h:
            return False
        for p in self.patterns:
            if _entry_matches_pattern(h, p):
                return True
        return False

    def validate_primary(self) -> None:
        """Called once at scan start. Raises if the primary is out of scope in strict mode."""
        if self.mode != "strict":
            return
        if not self.patterns:
            return  # No scope file -> nothing to validate against
        if not self.in_scope(self.primary):
            raise ScopeViolation(
                f"Primary target {self.primary!r} is not in scope. "
                f"Add it to your scope file or use --no-scope."
            )

    def check(self, host: str) -> "ScopeDecision":
        """
        Decide what to do with `host`. Returns a ScopeDecision; caller
        decides whether to honor `allow`.
        """
        allowed = self.in_scope(host)
        return ScopeDecision(host=host, allowed=allowed, mode=self.mode)


@dataclass
class ScopeDecision:
    host: str
    allowed: bool
    mode: str

    def __bool__(self) -> bool:  # truthy == allowed
        return self.allowed


class ScopeViolation(PermissionError):
    """Raised when the primary target is outside the agreed scope."""
    pass


def write_example_scope_file(path: str = "scope.txt") -> None:
    """Write a sample scope.txt to disk so the user has a starting point."""
    sample = """# Bug-bounty / pentest scope
# One pattern per line. Lines starting with # are comments.
#
# Patterns:
#   example.com      -> the apex + all subdomains
#   *.example.com    -> only subdomains (NOT the apex)
#   api.example.com  -> specific subdomain + its subdomains

example.com
"""
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(sample)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Backwards-compatible helper (used by attack_surface.py CLI)
# ---------------------------------------------------------------------------

def load_scope(path=None, primary: str = "", mode: str = "warn"):
    """
    Load a scope filter from a file. If no path is given, return a permissive
    filter that only contains the primary target.
    """
    if path:
        return ScopeFilter.from_file(primary=primary, path=path, mode=mode)
    # No file -> permissive filter (only the primary is in scope)
    return ScopeFilter(primary=primary, patterns=[], mode=mode)
