"""
core/wordlists.py
==================
Wordlist resolution for Kali-grade tooling.

Priority:
  1. --wordlist flag (explicit)
  2. $ATTACK_SURFACE_WORDLIST env
  3. Standard Kali/Debian paths:
       /usr/share/wordlists/attack-surface/subdomains.txt   (our .deb)
       /usr/share/dnsrecon/namelist.txt
       /usr/share/wordlists/SecLists/Discovery/DNS/   (deep, if present)
  4. Bundled wordlists/ (works on Termux & pip installs)

Also provides safe reuse of dirb's /usr/share/wordlists/dirb/common.txt
for future content-discovery features.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("AttackSurface.Wordlists")

BUNDLED = Path(__file__).resolve().parent.parent / "wordlists"

KALI_SUBDOMAIN_LISTS = [
    "/usr/share/wordlists/attack-surface/subdomains.txt",
    "/usr/share/dnsrecon/namelist.txt",
    "/usr/share/amass/wordlists/all.txt",
]

KALI_CONTENT_LISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/wordlists/dirb/big.txt",
]


def _first_existing(paths: List[str]) -> Optional[str]:
    for p in paths:
        if os.path.isfile(p):
            return p
    return None


def resolve_subdomains_wordlist(explicit: Optional[str] = None) -> str:
    """Return path of the best available subdomain wordlist."""
    candidates = []
    if explicit:
        candidates.append(explicit)
    env = os.environ.get("ATTACK_SURFACE_WORDLIST")
    if env:
        candidates.append(env)
    candidates.extend(KALI_SUBDOMAIN_LISTS)
    bundled = str(BUNDLED / "subdomains.txt")
    candidates.append(bundled)
    found = _first_existing(candidates)
    if not found:
        found = bundled
    logger.info("subdomain wordlist: %s", found)
    return found


def load_prefixes(explicit: Optional[str] = None,
                  max_entries: int = 5000) -> List[str]:
    """Load prefixes from the resolved wordlist (safe, capped)."""
    path = resolve_subdomains_wordlist(explicit)
    prefixes: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip()
                if w and not w.startswith("#"):
                    prefixes.append(w)
                if len(prefixes) >= max_entries:
                    logger.warning("wordlist truncated at %d entries", max_entries)
                    break
    except Exception as e:
        logger.warning("wordlist read failed: %s", e)
    return prefixes
