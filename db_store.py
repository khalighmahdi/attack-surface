"""attacksurface.db — central SQLite store for scan results (team mode).

Store every scan's findings, hosts, subdomains, and risk scores.
Enables: --list-scans, --compare, historical diffs, report generation.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from typing import Any, Optional

DB_DIR_DEFAULT = os.path.join(os.path.expanduser("~"), ".attack_surface")


def _connect(db_path: Optional[str] = None) -> tuple[sqlite3.Connection, str]:
    if db_path is None:
        db_path = os.path.join(DB_DIR_DEFAULT, "attacksurface.db")
    # Always expand ~ and handle relative paths (dirname may be "")
    db_path = os.path.expanduser(db_path)
    _dir = os.path.dirname(db_path)
    if _dir:
        os.makedirs(_dir, exist_ok=True)
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    return con, db_path


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    domain TEXT NOT NULL,
    tool_version TEXT,
    risk_score REAL,
    risk_level TEXT,
    summary TEXT,
    sections TEXT,
    cloud_assets TEXT,
    api_endpoints TEXT,
    api_fuzz_results TEXT,
    mitre_coverage TEXT,
    mitre_layer TEXT,
    sbom_analysis TEXT,
    auth_session TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host TEXT,
    title TEXT NOT NULL,
    severity TEXT,
    category TEXT,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    ip TEXT,
    protocol TEXT,
    ports TEXT,            -- JSON list
    tech TEXT,             -- JSON list
    headers_ok INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    subdomain TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
CREATE TABLE IF NOT EXISTS knull_memory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    domain TEXT,
    technique TEXT NOT NULL,
    target TEXT,
    outcome TEXT NOT NULL,     -- 'success' | 'failure' | 'pending'
    score REAL,                -- advisor score at the time
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_knull_memory_tech ON knull_memory(technique, domain);
CREATE TABLE IF NOT EXISTS knull_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL UNIQUE,
    ts_start TEXT,
    ts_end TEXT,
    domain TEXT,
    scan_id INTEGER,
    state TEXT,
    iteration INTEGER,
    max_iterations INTEGER,
    brain_calls INTEGER,
    prepared INTEGER,
    fired INTEGER,
    credentials INTEGER,
    kill_chain TEXT,
    moves TEXT,
    events TEXT
);
CREATE TABLE IF NOT EXISTS knull_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    agent_id TEXT,
    domain TEXT,
    technique TEXT,
    target TEXT,
    source TEXT,
    outcome TEXT,
    command TEXT,
    exit_code INTEGER,
    output TEXT
);
CREATE INDEX IF NOT EXISTS idx_knull_evidence_target
    ON knull_evidence(target, technique);
"""


def init_db(db_path: Optional[str] = None) -> None:
    con, _ = _connect(db_path)
    try:
        con.executescript(SCHEMA)
        # lightweight migration: sections column for structured scan data
        cols = {r[1] for r in con.execute("PRAGMA table_info(scans)")}
        if "sections" not in cols:
            con.execute("ALTER TABLE scans ADD COLUMN sections TEXT")
        # NEW: v0.19 columns
        for col in ("cloud_assets", "api_endpoints", "api_fuzz_results", "mitre_coverage", "mitre_layer", "sbom_analysis", "auth_session"):
            if col not in cols:
                con.execute(f"ALTER TABLE scans ADD COLUMN {col} TEXT")
        con.commit()
    finally:
        con.close()


def save_scan(results: dict[str, Any],
              domain: str,
              tool_version: str = "",
              db_path: Optional[str] = None) -> int:
    """Persist a scan result dict (the shape produced by the runner) into SQLite."""
    init_db(db_path)
    con, _ = _connect(db_path)
    try:
        risk = results.get("risk", {}) or {}
        summary = results.get("summary") or {}
        sections = results.get("sections") or {}
        cloud_assets = results.get("cloud_assets") or {}
        api_endpoints = results.get("api_endpoints") or []
        api_fuzz_results = results.get("api_fuzz_results") or []
        mitre_coverage = results.get("mitre_coverage") or {}
        mitre_layer = results.get("mitre_layer") or {}
        sbom_analysis = results.get("sbom_analysis")
        auth_session = results.get("auth_session")
        cur = con.execute(
            """INSERT INTO scans (ts, domain, tool_version, risk_score, risk_level, summary, sections,
                  cloud_assets, api_endpoints, api_fuzz_results, mitre_coverage, mitre_layer, sbom_analysis, auth_session)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                datetime.now().isoformat(timespec="seconds"),
                domain,
                tool_version,
                risk.get("overall_score"),
                risk.get("overall_level"),
                json.dumps(summary, ensure_ascii=False)[:4000],
                json.dumps(sections, ensure_ascii=False, default=str)[:100000],
                json.dumps(cloud_assets, ensure_ascii=False, default=str)[:100000],
                json.dumps(api_endpoints, ensure_ascii=False, default=str)[:100000],
                json.dumps(api_fuzz_results, ensure_ascii=False, default=str)[:100000],
                json.dumps(mitre_coverage, ensure_ascii=False, default=str)[:100000],
                json.dumps(mitre_layer, ensure_ascii=False, default=str)[:100000],
                json.dumps(sbom_analysis, ensure_ascii=False, default=str)[:100000] if sbom_analysis else None,
                auth_session,
            ),
        )
        scan_id = int(cur.lastrowid)

        # findings
        for host, flist in (results.get("findings") or {}).items():
            for f in flist:
                if isinstance(f, dict):
                    title = f.get("title") or str(f)[:200]
                    severity = f.get("severity")
                    category = f.get("category")
                else:
                    # plain string finding
                    title = str(f)[:200]
                    severity = None
                    category = None
                con.execute(
                    """INSERT INTO findings (scan_id, host, title, severity, category, detail)
                       VALUES (?,?,?,?,?,?)""",
                    (
                        scan_id, host,
                        title,
                        severity,
                        category,
                        json.dumps(f, ensure_ascii=False, default=str)[:2000],
                    ),
                )

        # hosts
        for h in results.get("hosts") or []:
            con.execute(
                """INSERT INTO hosts (scan_id, host, ip, protocol, ports, tech, headers_ok)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    scan_id,
                    h.get("host") or h.get("domain", ""),
                    h.get("ip"),
                    h.get("protocol"),
                    json.dumps(h.get("ports") or [], ensure_ascii=False),
                    json.dumps(h.get("tech") or [], ensure_ascii=False),
                    1 if h.get("headers_ok") else 0,
                ),
            )

        # subdomains
        for sub in results.get("subdomains") or []:
            con.execute("INSERT INTO subdomains (scan_id, subdomain) VALUES (?,?)",
                        (scan_id, sub))

        con.commit()
        return scan_id
    finally:
        con.close()


def list_scans(db_path: Optional[str] = None) -> list[dict[str, Any]]:
    init_db(db_path)
    con, _ = _connect(db_path)
    try:
        rows = con.execute(
            "SELECT id, ts, domain, risk_score, risk_level FROM scans "
            "ORDER BY ts DESC, id DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()


def get_scan(scan_id: int, db_path: Optional[str] = None) -> dict[str, Any]:
    """Full scan detail: summary + findings + hosts + subdomains."""
    init_db(db_path)
    con, _ = _connect(db_path)
    try:
        scan = con.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if scan is None:
            raise KeyError(f"scan {scan_id} not found")
        out = dict(scan)
        try:
            out["sections"] = json.loads(scan["sections"]) if scan["sections"] else {}
        except Exception:
            out["sections"] = {}
        try:
            out["cloud_assets"] = json.loads(scan["cloud_assets"]) if scan["cloud_assets"] else {}
        except Exception:
            out["cloud_assets"] = {}
        try:
            out["api_endpoints"] = json.loads(scan["api_endpoints"]) if scan["api_endpoints"] else []
        except Exception:
            out["api_endpoints"] = []
        try:
            out["api_fuzz_results"] = json.loads(scan["api_fuzz_results"]) if scan["api_fuzz_results"] else []
        except Exception:
            out["api_fuzz_results"] = []
        try:
            out["mitre_coverage"] = json.loads(scan["mitre_coverage"]) if scan["mitre_coverage"] else {}
        except Exception:
            out["mitre_coverage"] = {}
        try:
            out["mitre_layer"] = json.loads(scan["mitre_layer"]) if scan["mitre_layer"] else {}
        except Exception:
            out["mitre_layer"] = {}
        try:
            out["sbom_analysis"] = json.loads(scan["sbom_analysis"]) if scan["sbom_analysis"] else None
        except Exception:
            out["sbom_analysis"] = None
        out["auth_session"] = scan["auth_session"]
        out["findings"] = [dict(r) for r in con.execute(
            "SELECT * FROM findings WHERE scan_id=?", (scan_id,)).fetchall()]
        out["hosts"] = [dict(r) for r in con.execute(
            "SELECT * FROM hosts WHERE scan_id=?", (scan_id,)).fetchall()]
        out["subdomains"] = [r["subdomain"] for r in con.execute(
            "SELECT subdomain FROM subdomains WHERE scan_id=?", (scan_id,)).fetchall()]
        return out
    finally:
        con.close()


def latest_scan(domain: str, db_path: Optional[str] = None) -> Optional[dict[str, Any]]:
    init_db(db_path)
    con, _ = _connect(db_path)
    try:
        row = con.execute(
            "SELECT id FROM scans WHERE domain=? ORDER BY ts DESC LIMIT 1",
            (domain,),
        ).fetchone()
        if row is None:
            return None
        return get_scan(row["id"], db_path)
    finally:
        con.close()


def compare(scan_a: int, scan_b: int, db_path: Optional[str] = None) -> dict[str, Any]:
    """Diff two scans: new/gone subdomains, new findings, score delta."""
    a = get_scan(scan_a, db_path)
    b = get_scan(scan_b, db_path)
    subs_a, subs_b = set(a["subdomains"]), set(b["subdomains"])
    f_a = {(f["host"], f["title"]) for f in a["findings"]}
    f_b = {(f["host"], f["title"]) for f in b["findings"]}
    return {
        "scan_a": {"id": a["id"], "ts": a["ts"], "domain": a["domain"],
                   "score": a["risk_score"]},
        "scan_b": {"id": b["id"], "ts": b["ts"], "domain": b["domain"],
                   "score": b["risk_score"]},
        "score_delta": (b["risk_score"] or 0) - (a["risk_score"] or 0),
        "new_subdomains": sorted(subs_b - subs_a),
        "gone_subdomains": sorted(subs_a - subs_b),
        "new_findings": sorted(f_b - f_a),
        "fixed_findings": sorted(f_a - f_b),
    }


# ---------------------------------------------------------------------------
# Knull long-term memory
# ---------------------------------------------------------------------------

def knull_remember(technique: str,
                   outcome: str,
                   domain: Optional[str] = None,
                   target: Optional[str] = None,
                   score: Optional[float] = None,
                   detail: str = "",
                   db_path: Optional[str] = None) -> None:
    """Record one attempt outcome so Knull can learn from it.

    outcome: 'success' | 'failure' | 'pending'
    """
    from datetime import datetime, timezone
    init_db(db_path)
    con, _ = _connect(db_path)
    try:
        con.execute(
            "INSERT INTO knull_memory (ts, domain, technique, target, "
            "outcome, score, detail) VALUES (?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"),
             domain or "", technique, target or "", outcome, score, detail[:500]),
        )
        con.commit()
    finally:
        con.close()


def knull_stats(domain: Optional[str] = None,
                db_path: Optional[str] = None) -> dict[str, Any]:
    """Per-technique success/failure counts, optionally scoped to a domain.

    Returns {technique: {'success': n, 'failure': n, 'pending': n,
                         'attempts': n, 'success_rate': float}}.
    """
    init_db(db_path)
    con, _ = _connect(db_path)
    try:
        if domain:
            rows = con.execute(
                "SELECT technique, outcome, COUNT(*) AS c FROM knull_memory "
                "WHERE domain=? GROUP BY technique, outcome",
                (domain,),
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT technique, outcome, COUNT(*) AS c FROM knull_memory "
                "GROUP BY technique, outcome",
            ).fetchall()
        out: dict[str, Any] = {}
        for r in rows:
            t = r["technique"]
            e = out.setdefault(t, {"success": 0, "failure": 0, "pending": 0,
                                   "impact": 0, "attempts": 0,
                                   "success_rate": 0.0})
            if r["outcome"] in e:
                e[r["outcome"]] += r["c"]
        for e in out.values():
            decided = e["success"] + e["failure"]
            e["attempts"] = decided + e["pending"]
            e["success_rate"] = (e["success"] / decided) if decided else 0.0
        return out
    finally:
        con.close()


def knull_memory(limit: int = 50,
                 domain: Optional[str] = None,
                 db_path: Optional[str] = None) -> list[dict[str, Any]]:
    """Recent memory entries, newest first (for the dashboard panel)."""
    init_db(db_path)
    con, _ = _connect(db_path)
    try:
        if domain:
            rows = con.execute(
                "SELECT * FROM knull_memory WHERE domain=? "
                "ORDER BY id DESC LIMIT ?", (domain, limit)).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM knull_memory ORDER BY id DESC LIMIT ?",
                (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()

# ---------------------------------------------------------------------------
# Knull learning scoreboard
# ---------------------------------------------------------------------------

# Ordered longest-first so '[operator]' cannot shadow '[operator-x]'.
_MEMORY_SOURCES = ("[operator]", "[impact]", "[verify]", "[fired]", "[brain]")
_MEMORY_OUTCOMES = ("success", "failure", "pending", "impact")


def memory_source(detail: Optional[str]) -> str:
    """Where an attempt came from, read from the detail prefix Knull writes."""
    d = detail or ""
    for tag in _MEMORY_SOURCES:
        if d.startswith(tag):
            return tag.strip("[]")
    return "advisor"


def knull_scoreboard(domain: Optional[str] = None,
                     db_path: Optional[str] = None) -> dict[str, Any]:
    """Aggregate the memory table into a learning scoreboard.

    Answers the question the raw table cannot: *whose* picks are working —
    the LLM brain, the operator's manual fires, or the advisor's automatic
    ranking — and which techniques have worn themselves out.
    """
    init_db(db_path)
    con, _ = _connect(db_path)
    try:
        if domain:
            rows = [dict(r) for r in con.execute(
                "SELECT technique, outcome, detail, ts FROM knull_memory "
                "WHERE domain=? ORDER BY id", (domain,))]
        else:
            rows = [dict(r) for r in con.execute(
                "SELECT technique, outcome, detail, ts FROM knull_memory "
                "ORDER BY id")]
    finally:
        con.close()

    def blank() -> dict:
        return {"success": 0, "failure": 0, "pending": 0, "impact": 0,
                "attempts": 0, "decided": 0, "success_rate": 0.0}

    def finish(bucket: dict) -> dict:
        bucket["decided"] = bucket["success"] + bucket["failure"]
        bucket["attempts"] = bucket["decided"] + bucket["pending"]
        bucket["success_rate"] = round(
            bucket["success"] / bucket["decided"], 3
        ) if bucket["decided"] else 0.0
        return bucket

    by_technique: dict = {}
    by_source: dict = {}
    totals = blank()
    for r in rows:
        oc = r.get("outcome") or "pending"
        if oc not in _MEMORY_OUTCOMES:
            oc = "pending"
        src = memory_source(r.get("detail"))
        by_technique.setdefault(r.get("technique") or "?", blank())[oc] += 1
        by_source.setdefault(src, blank())[oc] += 1
        totals[oc] += 1

    for b in by_technique.values():
        finish(b)
    for b in by_source.values():
        finish(b)
    finish(totals)

    tech_rows = [dict(technique=t, **counts)
                 for t, counts in by_technique.items()]
    tech_rows.sort(key=lambda x: (-x["attempts"], -x["success_rate"]))

    # Tried at least 3 decided times and never once worked: Knull should
    # stop wasting iterations on these.
    worn_out = [t["technique"] for t in tech_rows
                if t["decided"] >= 3 and t["success"] == 0]

    return {
        "totals": totals,
        "by_source": by_source,
        "by_technique": tech_rows,
        "worn_out": worn_out,
        "n_records": len(rows),
        "updated_at": rows[-1]["ts"] if rows else "",
        "domain": domain or "",
    }


# ---------------------------------------------------------------------------
# Knull session history (survives a dashboard restart)
# ---------------------------------------------------------------------------

_RUN_COLUMNS = ("agent_id", "ts_start", "ts_end", "domain", "scan_id",
                "state", "iteration", "max_iterations", "brain_calls",
                "prepared", "fired", "credentials", "kill_chain", "moves",
                "events")


def save_knull_run(run: dict, db_path: Optional[str] = None) -> None:
    """Upsert one Knull session, keyed by agent_id.

    The in-memory _agent_instance is gone the moment the dashboard is
    restarted; this is what keeps the decision history (and therefore the
    chat's context and the operator's ability to review a run) intact.
    """
    if not run or not run.get("agent_id"):
        return
    init_db(db_path)
    con, _ = _connect(db_path)
    try:
        values = {
            "agent_id": str(run["agent_id"]),
            "ts_start": run.get("ts_start") or "",
            "ts_end": run.get("ts_end") or "",
            "domain": run.get("domain") or "",
            "scan_id": run.get("scan_id") or 0,
            "state": run.get("state") or "",
            "iteration": run.get("iteration") or 0,
            "max_iterations": run.get("max_iterations") or 0,
            "brain_calls": run.get("brain_calls") or 0,
            "prepared": run.get("prepared") or 0,
            "fired": run.get("fired") or 0,
            "credentials": run.get("credentials") or 0,
            "kill_chain": json.dumps(run.get("kill_chain") or {},
                                     ensure_ascii=False, default=str),
            "moves": json.dumps(run.get("moves") or [], ensure_ascii=False),
            "events": json.dumps(run.get("events") or [], ensure_ascii=False,
                                 default=str)[:200000],
        }
        cols = ", ".join(_RUN_COLUMNS)
        marks = ", ".join("?" for _ in _RUN_COLUMNS)
        updates = ", ".join(f"{c}=excluded.{c}"
                            for c in _RUN_COLUMNS if c != "agent_id")
        con.execute(
            f"INSERT INTO knull_runs ({cols}) VALUES ({marks}) "
            f"ON CONFLICT(agent_id) DO UPDATE SET {updates}",
            tuple(values[c] for c in _RUN_COLUMNS))
        con.commit()
    finally:
        con.close()


def list_knull_runs(limit: int = 20,
                    db_path: Optional[str] = None) -> list[dict[str, Any]]:
    """Most recent Knull sessions, newest first (events stripped)."""
    init_db(db_path)
    con, _ = _connect(db_path)
    try:
        rows = [dict(r) for r in con.execute(
            "SELECT * FROM knull_runs ORDER BY id DESC LIMIT ?", (limit,))]
    finally:
        con.close()
    for r in rows:
        r.pop("events", None)
        for key in ("kill_chain", "moves"):
            raw = r.get(key)
            if isinstance(raw, str):
                try:
                    r[key] = json.loads(raw)
                except (ValueError, TypeError):
                    r[key] = [] if key == "moves" else {}
    return rows


def get_knull_run(agent_id: str,
                  db_path: Optional[str] = None) -> Optional[dict[str, Any]]:
    """One full session, including its event log."""
    init_db(db_path)
    con, _ = _connect(db_path)
    try:
        row = con.execute("SELECT * FROM knull_runs WHERE agent_id=?",
                          (str(agent_id),)).fetchone()
    finally:
        con.close()
    if row is None:
        return None
    out = dict(row)
    for key in ("kill_chain", "moves", "events"):
        raw = out.get(key)
        if isinstance(raw, str):
            try:
                out[key] = json.loads(raw)
            except (ValueError, TypeError):
                out[key] = [] if key != "kill_chain" else {}
    return out


# ---------------------------------------------------------------------------
# Knull evidence vault — the raw proof behind every verdict
# ---------------------------------------------------------------------------

def save_evidence(row: dict, db_path: Optional[str] = None) -> None:
    """Store the raw output behind one verdict.

    A finding without proof is an opinion: this is what lets the operator
    (and the chat) ask 'show me the evidence' and get the actual response.
    """
    if not row:
        return
    init_db(db_path)
    con, _ = _connect(db_path)
    try:
        from datetime import datetime, timezone
        con.execute(
            "INSERT INTO knull_evidence (ts, agent_id, domain, technique, "
            "target, source, outcome, command, exit_code, output) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (row.get("ts") or datetime.now(timezone.utc)
                .isoformat(timespec="seconds"),
             str(row.get("agent_id") or ""),
             str(row.get("domain") or ""),
             str(row.get("technique") or ""),
             str(row.get("target") or ""),
             str(row.get("source") or ""),
             str(row.get("outcome") or ""),
             str(row.get("command") or "")[:400],
             row.get("exit_code"),
             str(row.get("output") or "")[:4000]))
        con.commit()
    finally:
        con.close()


def list_evidence(limit: int = 40,
                  target: Optional[str] = None,
                  db_path: Optional[str] = None) -> list[dict[str, Any]]:
    """Most recent evidence rows, newest first."""
    init_db(db_path)
    con, _ = _connect(db_path)
    try:
        if target:
            rows = con.execute(
                "SELECT * FROM knull_evidence WHERE target=? "
                "ORDER BY id DESC LIMIT ?", (target, limit)).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM knull_evidence ORDER BY id DESC LIMIT ?",
                (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()


def evidence_summary(db_path: Optional[str] = None) -> dict[str, Any]:
    """Counts per source/outcome, for the chat context."""
    init_db(db_path)
    con, _ = _connect(db_path)
    try:
        rows = con.execute(
            "SELECT source, outcome, COUNT(*) AS c FROM knull_evidence "
            "GROUP BY source, outcome").fetchall()
    finally:
        con.close()
    out: dict[str, Any] = {}
    for r in rows:
        out.setdefault(r["source"] or "?", {})[r["outcome"] or "?"] = r["c"]
    return out
