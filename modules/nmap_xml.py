"""
modules/nmap_xml.py
====================
Export port-scan results in **Nmap XML format** so any Kali tool
that parses nmap XML (Metasploit `db_import`, parse_nmap.py,
Zenmap, etc.) can consume our results directly.

Format reference: DTD at https://nmap.org/book/nmap-dtd.html
We emit the subset that downstream tools actually read:
<nmaprun><host><address><ports><port><state><service .../></port></ports></host></nmaprun>
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from xml.sax.saxutils import escape
from typing import Any, Dict

logger = logging.getLogger("AttackSurface.NmapXML")


def build_xml(ports: Dict[str, Dict[str, Any]], scanner_version: str = "0.11") -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<!DOCTYPE nmaprun SYSTEM "nmap.dtd">',
        '<nmaprun scanner="attack-surface" '
        f'args="attack-surface {scanner_version}" startstr="{now}" '
        f'version="{scanner_version}" xmloutputversion="1.05">',
    ]
    for host, info in (ports or {}).items():
        ip = (info.get("ip") if isinstance(info, dict) else "") or ""
        hostname = escape(str(host))
        lines.append('<host>')
        if ip:
            lines.append(f'<address addr="{escape(str(ip))}" addrtype="ipv4" />')
        lines.append(f'<hostnames><hostname name="{hostname}" type="PTR" /></hostnames>')
        lines.append('<ports>')
        for p in (info.get("open_ports") or []) if isinstance(info, dict) else []:
            pid = int(p.get("port", 0))
            proto = escape(str(p.get("protocol", "tcp")))
            state = "open"
            service = escape(str(p.get("service", "unknown")))
            banner = p.get("banner") or ""
            product, version = "", ""
            if banner:
                # "MariaDB 10.3.23 or earlier" -> product/version split
                parts = banner.split(" ", 1)
                product = escape(parts[0])
                if len(parts) > 1:
                    version = escape(parts[1])
            lines.append(
                f'<port protocol="{proto}" portid="{pid}">'
                f'<state state="{state}" />'
                f'<service name="{service}" product="{product}" version="{version}" '
                f'method="probed" conf="7" /></port>'
            )
        lines.append('</ports>')
        lines.append('</host>')
    lines.append('<runstats><finished timestr="' + now + '" /></runstats>')
    lines.append('</nmaprun>')
    return "\n".join(lines)


def write_xml(ports: Dict[str, Dict[str, Any]], path: str,
              scanner_version: str = "0.11") -> str:
    xml = build_xml(ports, scanner_version)
    with open(path, "w", encoding="utf-8") as f:
        f.write(xml)
    logger.info("nmap-xml written: %s", path)
    return path
