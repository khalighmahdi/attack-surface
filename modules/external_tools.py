"""
modules/external_tools.py
==========================
Kali-tool integrations: if a well-known recon tool is installed
(amass, subfinder, theHarvester), use it and merge its results into
the subdomain set. Every integration is optional and fail-soft —
the scanner always works without them.

Check what is available:
    python3 -c "from modules.external_tools import available; print(available())"
"""
from __future__ import annotations

import logging
import shutil
import subprocess
from typing import Dict, List

logger = logging.getLogger("AttackSurface.External")

TIMEOUT = 180


def available() -> Dict[str, bool]:
    return {
        name: bool(shutil.which(cmd))
        for name, cmd in (
            ("amass", "amass"),
            ("subfinder", "subfinder"),
            ("theharvester", "theHarvester"),
        )
    }


def amass_passive(domain: str) -> List[str]:
    """amass enum -passive -d <domain> (no active probing, polite)."""
    if not shutil.which("amass"):
        return []
    try:
        r = subprocess.run(
            ["amass", "enum", "-passive", "-d", domain, "-nocolor"],
            capture_output=True, text=True, timeout=TIMEOUT,
        )
        out = [l.strip().lower() for l in r.stdout.splitlines()
               if l.strip() and l.strip().endswith(domain)]
        logger.info("amass: %d subdomains", len(out))
        return out
    except Exception as e:
        logger.debug("amass failed: %s", e)
        return []


def subfinder_passive(domain: str) -> List[str]:
    """subfinder -d <domain> --silent (passive sources only)."""
    if not shutil.which("subfinder"):
        return []
    try:
        r = subprocess.run(
            ["subfinder", "-d", domain, "--silent"],
            capture_output=True, text=True, timeout=TIMEOUT,
        )
        out = [l.strip().lower() for l in r.stdout.splitlines()
               if l.strip() and l.strip().endswith(domain)]
        logger.info("subfinder: %d subdomains", len(out))
        return out
    except Exception as e:
        logger.debug("subfinder failed: %s", e)
        return []


def theharvester_emails(domain: str) -> List[str]:
    """theHarvester -d <domain> -b crtsh — returns emails found."""
    if not shutil.which("theHarvester"):
        return []
    try:
        r = subprocess.run(
            ["theHarvester", "-d", domain, "-b", "crtsh", "-l", "100"],
            capture_output=True, text=True, timeout=TIMEOUT,
        )
        import re
        emails = sorted(set(re.findall(
            r"[a-zA-Z0-9._%+-]+@" + re.escape(domain), r.stdout)))
        logger.info("theHarvester: %d emails", len(emails))
        return emails
    except Exception as e:
        logger.debug("theHarvester failed: %s", e)
        return []


def enrich_subdomains(domain: str, current: set) -> List[str]:
    """Merge external tools' subdomains into the current set.
    Returns list of NEW subdomains added."""
    tools = available()
    merged: List[str] = []
    if tools.get("amass"):
        merged += [h for h in amass_passive(domain) if h not in current]
    if tools.get("subfinder"):
        merged += [h for h in subfinder_passive(domain) if h not in current]
    for h in merged:
        current.add(h)
    if merged:
        logger.info("external tools added %d subdomains", len(merged))
    return merged
