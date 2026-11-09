"""Evidence proof-pack builder for bug-bounty / CTF submissions.

Produces a single `.zip` containing the canonical report artifacts plus a
signed (SHA-256) manifest — enough for a program to review without ever
needing the full scan again.
"""
from __future__ import annotations

import hashlib
import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List

ARTIFACTS = [
    "reports/output.json",
    "reports/output.csv",
    "reports/output.md",
    "reports/graph_data.json",
]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build(domain: str, report_dir: str = "reports") -> str | None:
    rd = Path(report_dir)
    out = rd / f"evidence_{domain}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.zip"
    out.parent.mkdir(parents=True, exist_ok=True)

    manifest = {"domain": domain, "created_utc": datetime.now(timezone.utc).isoformat(), "files": []}
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        # HTML reports (latest)
        for p in sorted(rd.glob("report_*.html")):
            z.write(p, arcname=f"reports/{p.name}")
            manifest["files"].append({"path": str(p), "sha256": _sha256(p)})
        for art in ARTIFACTS:
            pp = Path(art)
            if pp.exists():
                z.write(pp, arcname=art)
                manifest["files"].append({"path": art, "sha256": _sha256(pp)})
        graph = rd / "graph_data.json"
        if graph.exists() and str(graph) not in [m["path"] for m in manifest["files"]]:
            z.write(graph, arcname="reports/graph_data.json")
            manifest["files"].append({"path": str(graph), "sha256": _sha256(graph)})
        z.writestr("MANIFEST.json", json.dumps(manifest, indent=2, ensure_ascii=False))
    return str(out)
