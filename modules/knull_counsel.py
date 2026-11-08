"""KnullCounsel — talk to Knull in plain language.

The operator asks a question or gives an instruction; Knull answers from
WHAT IT ACTUALLY HAS (the scan, its memory, the scoreboard, chains, the
CVE watchlist, the prepared queue) instead of improvising, and may propose
actions.

Contract:
  * Only the context built here reaches the model — no other data source.
  * Actions are NEVER executed server-side. They are returned as a
    proposal for the operator to click, and each one still passes the
    endpoint's own scope/queue gates when it is finally run.
  * A reply must not invent numbers: the prompt forbids it and the
    context carries every figure the model may cite.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AttackSurface.KnullCounsel")

# Actions the UI knows how to offer. Anything else is rejected, so a
# hallucinated op can never reach an endpoint.
ALLOWED_OPS = {
    "fire": ("target_key",),
    "impact_start": ("target_key",),
    "record": ("technique", "target", "outcome"),
    "start_scan": ("domain",),
    "launch_agent": ("scan_id",),
    "build_graph": (),
    "show_scoreboard": (),
}

MAX_MESSAGE = 4000
MAX_HISTORY = 12
MAX_ACTIONS = 3

_SYSTEM = """You are Knull, the reasoning layer of an attack-surface scanner.
You are talking to the operator of this engagement.

RULES
1. Answer ONLY from the CONTEXT below. Never invent hosts, CVEs, scores or
   outcomes. If the context does not contain it, say exactly that.
2. Quote the real numbers when you use them (risk, counts, confidences).
3. Always reply in English, whatever language the question is in.
4. Be concise: 2-6 sentences unless they ask for a list.
5. You may propose up to 3 actions using the schema. Actions are NOT run
   automatically — the operator clicks them. Only propose an action that
   the context shows is possible (a target_key must appear in PREPARED).
6. When data is missing or stale, say what would have to be run to get it.

STYLE — talk like a colleague on shift, not like a product manual:
- Short direct sentences, plain words, no corporate filler ("I hope this
  helps", "It is worth noting", "In conclusion").
- Say "we" for what this tool did, "I" for your recommendation.
- If the answer is one number, give the number. Do not pad.
- Be blunt about bad news: an unreachable host, a failed technique, a
  keyword-only CVE. Call it what it is.
- One or two sentences of reasoning is enough; skip it when the data
  speaks for itself.

OUTPUT: JSON only, no prose around it:
{"reply": "<your answer>", "actions": [{"op": "<one of the allowed ops>",
 "target_key": "...", "technique": "...", "target": "...",
 "outcome": "success|failure", "domain": "...", "scan_id": 0}]}
Allowed ops: {ops}
Omit "actions" when you have nothing to propose.
"""


def _fmt_scan(scan: Optional[Dict[str, Any]]) -> str:
    if not scan:
        return "  (no scan)"
    sections = scan.get("sections") or {}
    if not isinstance(sections, dict):
        sections = {}
    reach = sections.get("reachability") or {}
    counts = {k: (len(v) if isinstance(v, (list, dict)) else 0)
              for k, v in sections.items()}
    counts = {k: v for k, v in counts.items() if v}
    tech = []
    for h in (scan.get("hosts") or []):
        t = h.get("tech")
        if isinstance(t, str):
            try:
                t = json.loads(t)
            except (ValueError, TypeError):
                t = []
        tech = tech or (t or [])
    lines = [
        f"  id=#{scan.get('id')} domain={scan.get('domain')} ts={scan.get('ts')}",
        f"  risk={scan.get('risk_score')} ({scan.get('risk_level')}) | "
        f"hosts={len(scan.get('hosts') or [])} findings="
        f"{len(scan.get('findings') or [])} subdomains="
        f"{len(scan.get('subdomains') or [])}",
        f"  reachability={reach.get('state', 'unknown')}"
        + (f" — {reach.get('note')}" if reach.get("note") else ""),
        f"  tech={tech or 'unknown'}",
        f"  populated sections={counts or 'none'}",
    ]
    return "\n".join(lines)


def _fmt_findings(scan: Optional[Dict[str, Any]], limit: int = 12) -> str:
    if not scan:
        return "  (none)"
    rows = []
    for f in (scan.get("findings") or []):
        title = str(f.get("title") or "").strip()
        if not title:
            continue
        sev = f.get("severity") or "?"
        rows.append(f"  [{sev}] {f.get('host', '?')}: {title[:110]}")
    if not rows:
        return "  (none)"
    return "\n".join(rows[:limit])


def build_context(db_path: Optional[str] = None,
                  agent: Any = None,
                  scan_id: Optional[int] = None) -> str:
    """Compact, factual context for one conversation turn."""
    import db_store

    scans = db_store.list_scans(db_path)
    scan = None
    if scan_id:
        try:
            scan = db_store.get_scan(int(scan_id), db_path)
        except Exception:
            scan = None
    if scan is None and scans:
        try:
            scan = db_store.get_scan(scans[0]["id"], db_path)
        except Exception:
            scan = None

    sb = db_store.knull_scoreboard(domain=(scan or {}).get("domain"),
                                   db_path=db_path)
    totals = sb.get("totals") or {}

    lines = ["[SCAN]"]
    lines.append(_fmt_scan(scan))

    lines.append("[FINDINGS]")
    lines.append(_fmt_findings(scan))

    lines.append("[LEARNING SCOREBOARD]")
    lines.append(
        f"  records={sb.get('n_records')} decided={totals.get('decided')} "
        f"success={totals.get('success')} failure={totals.get('failure')} "
        f"pending={totals.get('pending')} impact={totals.get('impact')}")
    by_src = sb.get("by_source") or {}
    if by_src:
        lines.append("  by source: " + "; ".join(
            f"{k}={v.get('decided', 0)}d/{v.get('success', 0)}ok"
            for k, v in by_src.items()))
    worn = sb.get("worn_out") or []
    lines.append(f"  worn_out (never worked after >=3 tries): {worn or 'none'}")
    tech_rows = [t for t in (sb.get("by_technique") or [])
                 if t.get("decided") or t.get("impact")][:6]
    for t in tech_rows:
        lines.append(f"    {t['technique']}: {t['decided']} decided, "
                     f"{t['success']} ok, {t['failure']} fail, "
                     f"rate={t['success_rate']}")

    if scan:
        from modules.attack_graph import find_chains
        try:
            chains = find_chains(scan)[:4]
        except Exception:
            chains = []
        lines.append("[CHAINS]")
        if chains:
            for c in chains:
                steps = " -> ".join(s.get("technique", "")
                                    for s in (c.get("steps") or []))
                lines.append(f"  [{c.get('confidence')}] {steps} "
                             f"p={c.get('probability')} — {c.get('reason')}")
        else:
            lines.append("  (none)")

    if scan:
        cves = (scan.get("sections") or {}).get("cves") or {}
        if isinstance(cves, dict) and cves:
            lines.append("[CVE WATCHLIST]")
            for host, rows in list(cves.items())[:3]:
                for row in (rows or [])[:2]:
                    if not isinstance(row, dict):
                        continue
                    ids = [c.get("id") or c.get("cve")
                           for c in (row.get("cves") or [])][:6]
                    lines.append(f"  {host} | {row.get('tech')} | "
                                 f"match={row.get('match')} | {ids}")

    runs = db_store.list_knull_runs(limit=5, db_path=db_path)
    lines.append("[SESSION HISTORY]")
    if runs:
        for r in runs:
            lines.append(
                f"  {r.get('agent_id')} end={r.get('ts_end') or '?'} "
                f"domain={r.get('domain') or '-'} state={r.get('state')} "
                f"iter={r.get('iteration')}/{r.get('max_iterations')} "
                f"brain_calls={r.get('brain_calls')} prepared={r.get('prepared')} "
                f"fired={r.get('fired')} moves={r.get('moves')}")
    else:
        lines.append("  (no sessions yet)")

    # What the tool actually proved — the raw responses behind verdicts.
    try:
        ev = db_store.list_evidence(limit=6, db_path=db_path)
    except Exception:
        ev = []
    lines.append("[EVIDENCE VAULT]")
    if ev:
        for e in ev:
            lines.append(
                f"  {e.get('source')}/{e.get('outcome')} "
                f"{e.get('technique')} on {e.get('target')} "
                f"exit={e.get('exit_code')} :: "
                f"{str(e.get('output') or '(none)')[:140]}")
    else:
        lines.append("  (nothing captured yet — no shot fired, no probe run)")

    lines.append("[KNULL STATE]")
    if agent is None:
        lines.append("  (no agent running)")
    else:
        try:
            st = agent.get_status()
        except Exception as e:
            st = {"error": str(e)}
        lines.append(f"  state={st.get('state')} iteration="
                     f"{st.get('iteration')}/{st.get('max_iterations')} "
                     f"running={st.get('running')}")
        lines.append("  kill_chain: " + ", ".join(
            f"{k}={v.get('status')}" for k, v in
            (st.get("kill_chain") or {}).items()))
        prep = st.get("prepared") or []
        lines.append("  PREPARED (target_key to fire):")
        for p in prep:
            lines.append(f"    {'[fired]' if p.get('fired') else '[ready]'} "
                         f"{p.get('target_key')} :: "
                         f"{str(p.get('command'))[:90]}")
        ev = st.get("events") or []
        if ev:
            lines.append("  last events:")
            for e in ev[-12:]:
                lines.append(f"    [{e.get('state')}] {e.get('action')}: "
                             f"{str(e.get('detail'))[:100]}")

    lines.append("[SCOPE]")
    if agent is not None:
        try:
            lines.append("  roots: " + ", ".join(agent.scope_roots()))
        except Exception:
            lines.append("  roots: unknown")
    else:
        lines.append(f"  roots: {(scan or {}).get('domain') or 'unknown'}")
    return "\n".join(lines)


def validate_actions(raw: Any) -> List[Dict[str, Any]]:
    """Keep only well-formed, whitelisted proposals."""
    out: List[Dict[str, Any]] = []
    if not isinstance(raw, list):
        return out
    for item in raw[:MAX_ACTIONS]:
        if not isinstance(item, dict):
            continue
        op = str(item.get("op") or "").strip()
        if op not in ALLOWED_OPS:
            logger.warning("counsel: rejected unknown op %r", op)
            continue
        required = ALLOWED_OPS[op]
        if any(item.get(f) in (None, "") for f in required):
            logger.warning("counsel: op %r missing required fields %s",
                           op, required)
            continue
        clean = {"op": op}
        for f in ("target_key", "technique", "target", "domain", "outcome"):
            if item.get(f) not in (None, ""):
                clean[f] = str(item[f])
        if item.get("scan_id") not in (None, ""):
            try:
                clean["scan_id"] = int(item["scan_id"])
            except (TypeError, ValueError):
                continue
        if op == "record" and clean.get("outcome") not in (
                "success", "failure", "pending"):
            continue
        out.append(clean)
    return out


def chat(message: str, history: Optional[List[Dict[str, str]]] = None,
         context: str = "", timeout: float = 90.0) -> Dict[str, Any]:
    """One conversational turn. Returns {'ok', 'reply', 'actions'}."""
    from modules.knull_brain import _settings, post_chat

    text = (message or "").strip()[:MAX_MESSAGE]
    if not text:
        return {"ok": False, "error": "empty message"}
    s = _settings()
    if not s["api_key"]:
        return {"ok": False, "error": "no LLM endpoint configured"}

    msgs: List[Dict[str, str]] = [
        # .replace, not .format: the prompt itself contains JSON braces
        # ("{\"reply\": ...}") which str.format would try to interpolate.
        {"role": "system", "content": _SYSTEM.replace(
            "{ops}", ", ".join(sorted(ALLOWED_OPS)))},
    ]
    for h in (history or [])[-MAX_HISTORY:]:
        if isinstance(h, dict) and h.get("role") in ("user", "assistant"):
            content = str(h.get("content") or "")[:2000]
            if content:
                msgs.append({"role": h["role"], "content": content})
    msgs.append({"role": "user",
                 "content": f"CONTEXT:\n{context[:7000]}\n\n"
                            f"OPERATOR: {text}"})

    err: List[str] = []
    data = post_chat({"model": s["model"], "messages": msgs,
                      "temperature": 0.3, "max_tokens": 900},
                     timeout=timeout, last_error=err)
    if not data:
        return {"ok": False,
                "error": f"LLM call failed after retry: {err[-1] if err else 'unknown'}"}
    try:
        content = (data.get("choices") or [{}])[0] \
            .get("message", {}).get("content", "")
    except Exception as e:
        return {"ok": False, "error": f"LLM reply unreadable: {e}"}

    from modules.knull_brain import _extract_json
    obj = _extract_json(content)
    if not obj:
        # Never drop the operator's question: fall back to raw text.
        return {"ok": True, "reply": (content or "").strip()[:4000],
                "actions": []}
    return {"ok": True,
            "reply": str(obj.get("reply") or content).strip()[:4000],
            "actions": validate_actions(obj.get("actions"))}
