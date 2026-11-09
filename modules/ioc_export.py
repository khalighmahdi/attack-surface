"""Blue-team IOC export for SIEM/Wazuh hand-off."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from core.context import ScanContext


def build(ctx: ScanContext) -> str:
    """Build a structured IOC artifact for `ctx`; return its file path."""
    rd = Path("reports")
    rd.mkdir(parents=True, exist_ok=True)
    safe = (ctx.domain or "target").replace("/", "_")
    path = rd / f"ioc_{safe}.json"

    iocs: Dict[str, List[Any]] = {
        "domain": ctx.domain,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "version": ctx.version,
        "subdomains": list(ctx.subdomains or []),
        "alive_hosts": [{"domain": h.get("domain"), "ip": h.get("ip"),
                         "protocol": h.get("protocol")} for h in (ctx.alive_hosts or [])],
        "open_ports": [],
        "admin_panels": [],
        "findings_count": 0,
        "risk_levels": {},
    }
    for host, pinfo in (ctx.ports or {}).items():
        for p in (pinfo.get("open_ports") or []):
            iocs["open_ports"].append({"host": host, "port": p.get("port"),
                                     "service": p.get("service"), "banner": p.get("banner")})
    iocs["admin_panels"] = (ctx.primary_admin_panels or ctx.admin_panels or [])
    iocs["findings_count"] = sum(len(v or []) for v in (ctx.findings or {}).values())
    iocs["risk_levels"] = {h: (v.get("level") if isinstance(v, dict) else None)
                           for h, v in (ctx.risk_scores or {}).items()}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(iocs, f, indent=2, ensure_ascii=False)
    return str(path)
