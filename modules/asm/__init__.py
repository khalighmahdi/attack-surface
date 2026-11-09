"""ASM Core — Continuous Attack Surface Management.

Capabilities:
- Asset Inventory: centralized registry of domains, IPs, cloud assets, technologies
- Delta Scanning: detect changes between scans (new subs, ports, tech, certs)
- Change Alerts: webhook/Telegram/Slack for new risky assets
- Scheduled Hunts: cron-based auto-hunt with persistence
- Multi-tenant/RBAC: teams, clients, projects with role-based access
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from core.scope import ScopeFilter

DB_PATH = Path(os.path.expanduser("~/.attack_surface/asm.db"))

logger = logging.getLogger("AttackSurface.ASM")


@dataclass
class Asset:
    id: Optional[int]
    asset_type: str  # domain, ip, cidr, cloud_resource, api_endpoint
    value: str
    source: str  # scan, manual, cloud_api, dns, certificate
    metadata: Dict[str, Any]
    risk_score: float
    risk_level: str
    owner: str
    tags: List[str]
    first_seen: str
    last_seen: str
    is_active: bool


@dataclass
class ChangeEvent:
    id: Optional[int]
    asset_id: int
    change_type: str  # added, removed, modified, risk_changed
    field: str
    old_value: str
    new_value: str
    severity: str  # info, low, medium, high, critical
    detected_at: str
    acknowledged: bool


class ASMDatabase:
    """Persistent asset inventory and change tracking."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_type TEXT NOT NULL,
                    value TEXT NOT NULL UNIQUE,
                    source TEXT NOT NULL,
                    metadata TEXT DEFAULT '{}',
                    risk_score REAL DEFAULT 0.0,
                    risk_level TEXT DEFAULT 'Low',
                    owner TEXT DEFAULT '',
                    tags TEXT DEFAULT '[]',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    is_active INTEGER DEFAULT 1
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS change_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER NOT NULL,
                    change_type TEXT NOT NULL,
                    field TEXT NOT NULL,
                    old_value TEXT,
                    new_value TEXT,
                    severity TEXT DEFAULT 'info',
                    detected_at TEXT NOT NULL,
                    acknowledged INTEGER DEFAULT 0,
                    FOREIGN KEY (asset_id) REFERENCES assets(id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    domain TEXT NOT NULL,
                    snapshot_type TEXT NOT NULL,
                    data_hash TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scheduled_hunts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    cron_expr TEXT NOT NULL,
                    hunt_config TEXT DEFAULT '{}',
                    last_run TEXT,
                    next_run TEXT,
                    enabled INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_value ON assets(value)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_changes_asset ON change_events(asset_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_snapshots_domain ON scan_snapshots(domain)")

    def upsert_asset(self, asset: Asset) -> int:
        now = datetime.utcnow().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                "SELECT id, metadata, risk_score, risk_level, tags FROM assets WHERE value=?",
                (asset.value,))
            row = cur.fetchone()
            if row:
                old_meta = json.loads(row[1]) if row[1] else {}
                old_score = row[2]
                old_level = row[3]
                old_tags = json.loads(row[4]) if row[4] else []
                changes = []
                if old_score != asset.risk_score:
                    changes.append(("risk_score", str(old_score), str(asset.risk_score),
                                   self._score_severity(old_score, asset.risk_score)))
                if old_level != asset.risk_level:
                    changes.append(("risk_level", old_level, asset.risk_level, "medium"))
                if set(old_tags) != set(asset.tags):
                    changes.append(("tags", ",".join(old_tags), ",".join(asset.tags), "low"))
                conn.execute("""
                    UPDATE assets SET metadata=?, risk_score=?, risk_level=?, tags=?, last_seen=?, is_active=?
                    WHERE id=?
                """, (json.dumps(asset.metadata), asset.risk_score, asset.risk_level,
                      json.dumps(asset.tags), now, int(asset.is_active), row[0]))
                asset_id = row[0]
                for field, old, new, sev in changes:
                    self._record_change(conn, asset_id, "modified", field, old, new, sev)
            else:
                conn.execute("""
                    INSERT INTO assets (asset_type, value, source, metadata, risk_score, risk_level,
                                     owner, tags, first_seen, last_seen, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (asset.asset_type, asset.value, asset.source, json.dumps(asset.metadata),
                      asset.risk_score, asset.risk_level, asset.owner,
                      json.dumps(asset.tags), now, now, int(asset.is_active)))
                asset_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                self._record_change(conn, asset_id, "added", "asset", "", asset.value, "info")
            return asset_id

    def _score_severity(self, old: float, new: float) -> str:
        if new >= 90 and old < 90:
            return "critical"
        if new >= 70 and old < 70:
            return "high"
        if new >= 40 and old < 40:
            return "medium"
        if new > old:
            return "low"
        return "info"

    def _record_change(self, conn: sqlite3.Connection, asset_id: int, change_type: str,
                       field: str, old: str, new: str, severity: str):
        now = datetime.utcnow().isoformat()
        conn.execute("""
            INSERT INTO change_events (asset_id, change_type, field, old_value, new_value, severity, detected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (asset_id, change_type, field, old, new, severity, now))

    def get_unacknowledged_changes(self, severity: Optional[str] = None) -> List[ChangeEvent]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            q = "SELECT * FROM change_events WHERE acknowledged=0"
            params = []
            if severity:
                q += " AND severity=?"
                params.append(severity)
            q += " ORDER BY detected_at DESC"
            rows = conn.execute(q, params).fetchall()
            return [ChangeEvent(**dict(r)) for r in rows]

    def acknowledge_change(self, change_id: int):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE change_events SET acknowledged=1 WHERE id=?", (change_id,))

    def save_snapshot(self, scan_id: int, domain: str, snapshot_type: str, data: Any):
        import hashlib
        data_json = json.dumps(data, sort_keys=True)
        data_hash = hashlib.sha256(data_json.encode()).hexdigest()[:32]
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO scan_snapshots (scan_id, domain, snapshot_type, data_hash, data_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (scan_id, domain, snapshot_type, data_hash, data_json, datetime.utcnow().isoformat()))

    def get_latest_snapshot(self, domain: str, snapshot_type: str) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("""
                SELECT * FROM scan_snapshots
                WHERE domain=? AND snapshot_type=?
                ORDER BY created_at DESC LIMIT 1
            """, (domain, snapshot_type)).fetchone()
            if row:
                return json.loads(row["data_json"])
            return None

    def compare_snapshots(self, domain: str, snapshot_type: str, current_data: Any) -> List[Dict[str, Any]]:
        prev = self.get_latest_snapshot(domain, snapshot_type)
        if not prev:
            return [{"type": "baseline", "data": current_data}]
        return self._diff_data(prev, current_data, snapshot_type)

    def _diff_data(self, old: Any, new: Any, snapshot_type: str) -> List[Dict[str, Any]]:
        def load(item: Any) -> Any:
            """Set members were stringified: dicts round-trip, plain
            strings (subdomains) do not — json.loads raised on every
            added subdomain and killed the whole ASM pass."""
            try:
                return json.loads(item)
            except (ValueError, TypeError):
                return item

        def norm(f: Any) -> Dict[str, Any]:
            """Normalise a finding so (host, title) is a stable key."""
            if isinstance(f, dict):
                return {"host": f.get("host"),
                        "title": f.get("title") or f.get("finding") or "",
                        "raw": f}
            return {"host": None, "title": str(f)[:200], "raw": str(f)[:200]}

        changes = []
        if snapshot_type in ("subdomains", "ports", "tech"):
            old_set = set(json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
                          for item in (old if isinstance(old, list) else []))
            new_set = set(json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
                          for item in (new if isinstance(new, list) else []))
            added = new_set - old_set
            removed = old_set - new_set
            for item in added:
                changes.append({"type": "added", "snapshot_type": snapshot_type, "value": load(item)})
            for item in removed:
                changes.append({"type": "removed", "snapshot_type": snapshot_type, "value": load(item)})
        elif snapshot_type == "findings":
            old_map = {(n["host"], n["title"]): n["raw"]
                       for n in map(norm, old if isinstance(old, list) else [])}
            new_map = {(n["host"], n["title"]): n["raw"]
                       for n in map(norm, new if isinstance(new, list) else [])}
            for k, v in new_map.items():
                if k not in old_map:
                    changes.append({"type": "new_finding", "finding": v})
            for k, v in old_map.items():
                if k not in new_map:
                    changes.append({"type": "resolved_finding", "finding": v})
        return changes

    def add_scheduled_hunt(self, name: str, domain: str, cron_expr: str,
                           hunt_config: Dict[str, Any]) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("""
                INSERT INTO scheduled_hunts (name, domain, cron_expr, hunt_config, next_run, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (name, domain, cron_expr, json.dumps(hunt_config),
                  self._next_cron(cron_expr), datetime.utcnow().isoformat()))
            return cur.lastrowid

    def _next_cron(self, cron_expr: str) -> str:
        from datetime import datetime, timedelta
        return (datetime.utcnow() + timedelta(hours=1)).isoformat()

    def get_due_hunts(self) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            now = datetime.utcnow().isoformat()
            rows = conn.execute("""
                SELECT * FROM scheduled_hunts WHERE enabled=1 AND next_run <= ?
            """, (now,)).fetchall()
            return [dict(r) for r in rows]

    def update_hunt_run(self, hunt_id: int):
        with sqlite3.connect(self.db_path) as conn:
            next_run = self._next_cron(
                conn.execute("SELECT cron_expr FROM scheduled_hunts WHERE id=?", (hunt_id,)).fetchone()[0]
            )
            conn.execute("UPDATE scheduled_hunts SET last_run=?, next_run=? WHERE id=?",
                         (datetime.utcnow().isoformat(), next_run, hunt_id))


class DeltaScanner:
    """Detect and alert on attack surface changes."""

    def __init__(self, db: ASMDatabase):
        self.db = db

    def process_scan(self, scan_id: int, domain: str, scan_results: Dict[str, Any],
                     scope: ScopeFilter) -> List[Dict[str, Any]]:
        all_changes = []

        subs = scan_results.get("subdomains", [])
        sub_changes = self.db.compare_snapshots(domain, "subdomains", subs)
        self.db.save_snapshot(scan_id, domain, "subdomains", subs)
        for ch in sub_changes:
            if ch["type"] == "added":
                self._add_subdomain_asset(domain, ch["value"], scan_results)
            all_changes.append(ch)

        hosts = scan_results.get("hosts", [])
        port_data = []
        for h in hosts:
            if isinstance(h, dict):
                for p in h.get("ports", []):
                    port_data.append({"host": h.get("host"), "port": p})
        port_changes = self.db.compare_snapshots(domain, "ports", port_data)
        self.db.save_snapshot(scan_id, domain, "ports", port_data)
        all_changes.extend(port_changes)

        tech_data = scan_results.get("technologies", {})
        tech_list = []
        for host, techs in tech_data.items():
            for t in techs:
                tech_list.append({"host": host, "tech": t})
        tech_changes = self.db.compare_snapshots(domain, "tech", tech_list)
        self.db.save_snapshot(scan_id, domain, "tech", tech_list)
        all_changes.extend(tech_changes)

        findings = scan_results.get("findings", [])
        finding_changes = self.db.compare_snapshots(domain, "findings", findings)
        self.db.save_snapshot(scan_id, domain, "findings", findings)
        all_changes.extend(finding_changes)

        self._update_assets_from_findings(domain, findings)

        return all_changes

    def _add_subdomain_asset(self, domain: str, subdomain: str, scan_results: Dict):
        hosts = scan_results.get("hosts", [])
        ip = None
        for h in hosts:
            if isinstance(h, dict) and h.get("host") == subdomain:
                ip = h.get("ip")
                break
        asset = Asset(
            id=None,
            asset_type="domain",
            value=subdomain,
            source="subdomain_enum",
            metadata={"parent_domain": domain, "ip": ip},
            risk_score=0.0,
            risk_level="Low",
            owner="",
            tags=["subdomain"],
            first_seen=datetime.utcnow().isoformat(),
            last_seen=datetime.utcnow().isoformat(),
            is_active=True
        )
        self.db.upsert_asset(asset)

    def _update_assets_from_findings(self, domain: str, findings: List[Dict]):
        for f in findings:
            host = f.get("host") or domain
            severity = f.get("severity", "info")
            score = {"critical": 95, "high": 75, "medium": 50, "low": 25, "info": 10}.get(severity, 10)
            asset = Asset(
                id=None,
                asset_type="domain",
                value=host,
                source="finding",
                metadata={"finding": f.get("title"), "category": f.get("category")},
                risk_score=score,
                risk_level=severity.capitalize(),
                owner="",
                tags=["finding", severity],
                first_seen=datetime.utcnow().isoformat(),
                last_seen=datetime.utcnow().isoformat(),
                is_active=True
            )
            self.db.upsert_asset(asset)