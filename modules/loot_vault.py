"""Offline loot vault for credentials / findings / interesting artifacts.

Everything is stored as.append-only JSONL under ~/.attack_surface/loot so two
runs of the same target never silently overwrite prior evidence.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List


def _vault_dir(db_path: str | None = None) -> Path:
    base = db_path or os.environ.get("ATTACK_SURFACE_DB_PATH")
    root = os.path.dirname(os.path.expanduser(base)) if base else os.path.join(os.path.expanduser("~"), ".attack_surface")
    d = Path(root) / "loot"
    d.mkdir(parents=True, exist_ok=True)
    return d


def record(item: Dict[str, Any], db_path: str | None = None, dedup: bool = True) -> Dict[str, Any]:
    """Append a loot item (tagged). Returns the stored record."""
    vdir = _vault_dir(db_path)
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tag": item.get("tag", "finding"),
        "domain": item.get("domain"),
        "type": item.get("type"),
        "description": item.get("description") or item.get("evidence"),
        "source": item.get("source", "scan"),
        "extra": item.get("extra") or {},
    }
    q = json.dumps(rec, sort_keys=True, ensure_ascii=False)
    path = vdir / "loot.jsonl"
    if dedup and path.exists():
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip() == q:
                    return rec
    with open(path, "a", encoding="utf-8") as f:
        f.write(q + "\n")
    return rec


def record_from_findings(findings: Dict[str, List[str]] | None, db_path: str | None = None) -> int:
    """Extract simple loot items from a findings dict.

    Returns number of items added.
    """
    n = 0
    for host, items in (findings or {}).items():
        for desc in items or []:
            tag = "critical" if "critical" in desc.lower() else ("admin" if "admin" in desc.lower() else "finding")
            record({"tag": tag, "domain": host, "type": "finding", "description": desc, "source": "scan"}, db_path)
            n += 1
    return n


def list_items(tag: str | None = None, db_path: str | None = None, limit: int = 200) -> List[Dict[str, Any]]:
    vdir = _vault_dir(db_path)
    path = vdir / "loot.jsonl"
    out: List[Dict[str, Any]] = []
    if not path.exists():
        return out
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if tag and rec.get("tag") != tag:
                continue
            out.append(rec)
            if len(out) >= limit:
                break
    return out


def export_csv(db_path: str | None = None, out: str | None = None) -> str:
    import csv
    vdir = _vault_dir(db_path)
    rows = list_items(db_path=db_path, limit=10000)
    if out is None:
        out = str(vdir / "loot_export.csv")
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["ts", "tag", "domain", "type", "description", "source"])
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k) for k in ("ts", "tag", "domain", "type", "description", "source")})
    return out


def summary(db_path: str | None = None) -> Dict[str, int]:
    from collections import Counter
    c = Counter(r.get("tag", "unknown") for r in list_items(db_path=db_path, limit=100000))
    return dict(c)
