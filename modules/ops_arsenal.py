"""Arsenal — concrete, ready-to-run actions derived from what we found.

Everything here comes from data already on disk: Knull's prepared queue,
the attack chains, the enriched CVE watchlist (Metasploit module paths,
Exploit-DB ids) and the findings themselves. No network calls: this is a
button that hands the operator a command, not a scanner.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AttackSurface.Arsenal")


def _finding_actions(host: str, title: str) -> List[Dict[str, str]]:
    """Map a finding to the tool an operator would actually reach for."""
    t = (title or "").lower()
    host = (host or "").strip()
    if not host:
        return []
    url = f"https://{host}"
    out: List[Dict[str, str]] = []
    if "admin" in t or "panel" in t:
        out.append({"label": "probe panels with nuclei",
                    "tool": "nuclei",
                    "cmd": f"nuclei -u {url} -t http/exposures/panels/ "
                           f"-severity info,low,medium,high,critical"})
    if "missing" in t and "header" in t:
        out.append({"label": "re-check headers",
                    "tool": "curl",
                    "cmd": f"curl -sI {url} | grep -iE "
                           f"'strict-transport|content-security|x-frame|"
                           f"x-content-type|referrer'"})
    if "public exposure" in t or "open on port" in t:
        port = ""
        for word in t.split():
            if word.isdigit():
                port = word
                break
        if port:
            out.append({"label": f"enumerate port {port}",
                        "tool": "nmap",
                        "cmd": f"nmap -sV -sC -p {port} {host}"})
    if "wordpress" in t:
        out.append({"label": "wordpress audit",
                    "tool": "wpscan",
                    "cmd": f"wpscan --url {url} --enumerate vp,vt,u"})
    if "sql" in t and "inject" in t:
        out.append({"label": "confirm SQLi",
                    "tool": "sqlmap",
                    "cmd": f"sqlmap -u '{url}/?id=1' --batch --level 3 "
                           f"--risk 2"})
    if "spoof" in t or "spf" in t or "dmarc" in t:
        out.append({"label": "check email security",
                    "tool": "dig",
                    "cmd": f"dig +short TXT {host} && dig +short TXT "
                           f"_dmarc.{host}"})
    return out[:3]


def _cve_actions(host: str, row: Dict[str, Any],
                 limit: int = 6) -> List[Dict[str, Any]]:
    """Per-CVE actions, using the enrichment we already cached."""
    out: List[Dict[str, Any]] = []
    for c in (row.get("cves") or [])[:limit]:
        if not isinstance(c, dict):
            continue
        cid = str(c.get("cve") or c.get("id") or "")
        if not cid:
            continue
        cmds: List[Dict[str, str]] = []
        modules = c.get("metasploit") or []
        first = modules[0] if modules else None
        path = (first or {}).get("path") if isinstance(first, dict) else None
        if path:
            cmds.append({
                "label": f"metasploit: {path}",
                "tool": "msfconsole",
                "cmd": f"msfconsole -qx \"use {path}; set RHOSTS {host}; "
                       f"set LHOST <your-ip>; run\""})
        edb = c.get("exploitdb")
        if edb:
            cmds.append({"label": f"exploit-db {edb}",
                         "tool": "searchsploit",
                         "cmd": f"searchsploit {cid}"})
        cmds.append({"label": "search local exploits",
                     "tool": "searchsploit",
                     "cmd": f"searchsploit {cid}"})
        out.append({
            "cve": cid,
            "cvss": c.get("cvss"),
            "kev": bool(c.get("kev")),
            "match": row.get("match") or "keyword",
            "tech": row.get("tech") or "",
            "summary": str(c.get("summary") or "")[:180],
            "commands": cmds,
        })
    return out


def ready_actions(db_path: Optional[str] = None, agent: Any = None,
                  scan_id: Optional[int] = None) -> Dict[str, Any]:
    """Everything an operator can run right now, in one list."""
    import db_store

    scan = None
    if scan_id:
        try:
            scan = db_store.get_scan(int(scan_id), db_path)
        except Exception:
            scan = None
    if scan is None:
        rows = db_store.list_scans(db_path)
        if rows:
            scan = db_store.get_scan(rows[0]["id"], db_path)
    scan = scan or {}

    prepared: List[Dict[str, Any]] = []
    if agent is not None:
        try:
            prepared = agent.prepared_commands()
        except Exception as e:
            logger.warning("arsenal: prepared queue unreadable: %s", e)

    chains: List[Dict[str, Any]] = []
    if scan:
        try:
            from modules.attack_graph import find_chains
            chains = [
                {"id": c.get("id"), "confidence": c.get("confidence"),
                 "probability": c.get("probability"),
                 "reason": c.get("reason"),
                 "steps": [{"n": s.get("n"), "technique": s.get("technique"),
                            "target": s.get("target"),
                            "command": s.get("command")}
                           for s in (c.get("steps") or [])]}
                for c in (find_chains(scan)[:4])]
        except Exception as e:
            logger.warning("arsenal: chains unavailable: %s", e)

    cves: List[Dict[str, Any]] = []
    sections = scan.get("sections") or {}
    cve_map = sections.get("cves") or {}
    if isinstance(cve_map, dict):
        for host, rows in list(cve_map.items())[:3]:
            for row in (rows or [])[:1]:
                if isinstance(row, dict):
                    cves.extend(_cve_actions(str(host), row))

    findings: List[Dict[str, Any]] = []
    for f in (scan.get("findings") or [])[:40]:
        title = str(f.get("title") or "")
        host = str(f.get("host") or scan.get("domain") or "")
        acts = _finding_actions(host, title)
        if acts:
            findings.append({"host": host, "finding": title.replace("**", "")[:120],
                             "actions": acts})

    return {
        "target": scan.get("domain"),
        "scan_id": scan.get("id"),
        "prepared": prepared,
        "chains": chains,
        "cves": cves,
        "findings": findings[:12],
        "totals": {"prepared": len(prepared), "chains": len(chains),
                   "cves": len(cves), "findings": len(findings)},
    }
