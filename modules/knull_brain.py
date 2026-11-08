"""KnullBrain — the LLM reasoning layer for Knull.

Design contract (safety):
  * The LLM *advises*; it never composes shell commands. The command
    Knull runs always comes from our own command_template.
  * Its output is a hypothesis: which technique, on which target, and
    why — validated against ATTACK_TECHNIQUES and the known host list.
  * Anything invalid (unknown technique, unknown host, malformed JSON,
    timeout, no key) is dropped and Knull falls back to the advisor's
    ranking. The brain is an accelerator, never a dependency.
  * Every hypothesis and its outcome goes into knull_memory so we can
    measure whether LLM advice actually beats the baseline.

Configuration (all optional):
  ATTACK_SURFACE_LLM_BASE_URL   default: http://127.0.0.1:20128/v1
  ATTACK_SURFACE_LLM_API_KEY    default: (none)
  ATTACK_SURFACE_LLM_MODEL      default: myai
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AttackSurface.KnullBrain")

_JSON_FENCE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.S)


def _settings() -> Dict[str, str]:
    base = (os.environ.get("ATTACK_SURFACE_LLM_BASE_URL")
            or os.environ.get("KNOLL_LLM_BASE_URL")
            or "http://127.0.0.1:20128/v1").rstrip("/")
    key = (os.environ.get("ATTACK_SURFACE_LLM_API_KEY")
           or os.environ.get("KNOLL_LLM_API_KEY")
           or "")
    model = (os.environ.get("ATTACK_SURFACE_LLM_MODEL")
             or os.environ.get("KNOLL_LLM_MODEL")
             or "myai")
    return {"base_url": base, "api_key": key, "model": model}


def available(timeout: float = 4.0) -> bool:
    """True when an OpenAI-compatible endpoint answers /models."""
    s = _settings()
    if not s["api_key"]:
        return False
    try:
        import requests
        r = requests.get(f"{s['base_url']}/models",
                         headers={"Authorization": f"Bearer {s['api_key']}"},
                         timeout=timeout)
        return r.status_code == 200
    except Exception:
        return False


# Statuses worth retrying: this provider has answered 410 for a
# deprecated model and 503 under load — both clear on a second try.
RETRY_STATUS = (410, 429, 500, 502, 503, 504)


def post_chat(payload: Dict[str, Any], timeout: float = 60.0,
              retries: int = 1,
              last_error: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
    """POST a chat/completions payload, retrying transient failures.

    Returns the parsed JSON body, or None when the call failed for good.
    Without this the operator sees a raw 'LLM returned 410' for an error
    that clears itself on the next try.
    """
    import time as _time

    s = _settings()
    if not s["api_key"]:
        return None
    import requests

    url = f"{s['base_url']}/chat/completions"
    headers = {"Authorization": f"Bearer {s['api_key']}",
               "Content-Type": "application/json"}
    last = "no attempt"
    for attempt in range(retries + 1):
        try:
            r = requests.post(url, headers=headers, json=payload,
                              timeout=timeout)
            if r.status_code == 200:
                return r.json()
            last = f"HTTP {r.status_code}"
            logger.warning("llm %s (attempt %d/%d)", last, attempt + 1,
                           retries + 1)
            if r.status_code not in RETRY_STATUS:
                return None
        except Exception as e:
            last = str(e)[:200]
            logger.warning("llm call failed (%s) (attempt %d/%d)",
                           last, attempt + 1, retries + 1)
        if attempt < retries:
            _time.sleep(1.5 * (attempt + 1))
    logger.warning("llm giving up after %d attempt(s): %s", retries + 1, last)
    if last_error is not None:
        last_error.append(last)
    return None


def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    """Pull the first JSON object out of a model reply (handles fences)."""
    if not text:
        return None
    m = _JSON_FENCE.search(text)
    candidate = m.group(1) if m else text
    # raw object
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        obj = json.loads(candidate[start:end + 1])
    except (ValueError, TypeError):
        return None
    return obj if isinstance(obj, dict) else None


def _build_prompt(brief: Dict[str, Any]) -> str:
    hosts = brief.get("hosts") or []
    host_lines = []
    for h in hosts[:40]:
        ports = h.get("ports") or []
        host_lines.append(f"  - {h.get('host')} ports={ports}")
    findings = brief.get("findings") or []
    finding_lines = [f"  - {f}" for f in findings[:25]]
    memory = brief.get("memory") or {}
    mem_lines = [f"  - {k}: {v}" for k, v in list(memory.items())[:20]]
    chains = brief.get("chains") or []
    chain_lines = []
    for c in chains[:5]:
        steps = " -> ".join(s.get("technique", "")
                            for s in (c.get("steps") or []))
        chain_lines.append(f"  - [{c.get('confidence')}] {steps} "
                           f"(p={c.get('probability')})")
    tried = brief.get("tried") or []
    kc = brief.get("kill_chain") or {}
    kc_line = ", ".join(f"{k}={v}" for k, v in kc.items())
    techniques = brief.get("techniques") or []

    return f"""You are the reasoning layer of Knull, an autonomous attack-surface
engineer. Pick exactly ONE next move.

TARGET SCOPE: {brief.get('domain', '?')}
DO NOT suggest anything out of scope.

HOSTS AND OPEN PORTS:
{chr(10).join(host_lines) or '  (none recorded)'}

FINDINGS:
{chr(10).join(finding_lines) or '  (none)'}

KILL CHAIN STATE: {kc_line or 'unknown'}
CREDENTIALS ALREADY HELD: {brief.get('credentials_held', 0)} (if >0, prefer
techniques that can reuse them)

MEMORY — outcomes of previous attempts (learn from these):
{chr(10).join(mem_lines) or '  (no history)'}

YOUR OWN PAST HYPOTHESES AND WHAT ACTUALLY HAPPENED (never repeat a refuted idea):
{chr(10).join('  - ' + h for h in (brief.get('brain_history') or [])) or '  (none yet — this is your first call)'}

SESSION MEMORY — brain decisions persisted across runs for this domain
(should this still be offered? was it refuted? did it work?):
{chr(10).join('  - ' + h for h in (brief.get('brain_sessions') or [])) or '  (no cross-run memory yet)'}

ALREADY TRIED THIS RUN (do not repeat):
{chr(10).join('  - ' + t for t in tried) or '  (nothing yet)'}

PRECOMPUTED CHAINS:
{chr(10).join(chain_lines) or '  (none)'}

ALLOWED TECHNIQUES (use the exact key): {', '.join(techniques)}

RULES
- Choose one ALLOWED technique key and one host from HOSTS.
- Prefer a move that advances the furthest incomplete kill-chain phase.
- Never repeat a failed attempt for the same technique on the same host.
- Base the hypothesis on the evidence above, not on speculation.

Reply with JSON ONLY, no prose, in this exact shape:
{{"hypothesis": "<one or two sentences: what you expect to gain>",
  "next": {{"technique": "<allowed key>", "target": "<host from HOSTS>"}},
  "alternatives": [
    {{"technique": "<allowed key>", "target": "<host from HOSTS>",
      "confidence": <0.0 to 1.0>}}
  ],
  "skip": ["<technique keys to avoid>"],
  "confidence": <0.0 to 1.0>}}

Give up to 2 alternatives ordered by preference: the caller falls through
them when your first option is not scored as viable. Use a low confidence
number when the evidence is thin — an option below 0.5 is discarded."""


def hypothesize_options(brief: Dict[str, Any],
                        timeout: float = 60.0) -> List[Dict[str, Any]]:
    """Ask the LLM for a ranked list of moves.

    Returns the primary hypothesis first, then any validated alternatives,
    so the caller can fall through when the top pick is not scored as
    viable. Validation is strict: unknown technique keys or hosts are
    rejected so a hallucinated target can never reach the executor.
    """
    s = _settings()
    if not s["api_key"]:
        return []

    allowed = set(brief.get("techniques") or [])
    hosts = {h.get("host") for h in (brief.get("hosts") or []) if h.get("host")}

    # one retry covers the transient provider errors we have actually seen
    data = post_chat({"model": s["model"],
                      "messages": [
                          {"role": "system",
                           "content": "You output JSON only. Never suggest shell "
                                      "syntax; you only name a technique key and "
                                      "a target host."},
                          {"role": "user", "content": _build_prompt(brief)},
                      ],
                      "temperature": 0.2,
                      "max_tokens": 700},
                     timeout=timeout)
    if not data:
        return []
    try:
        content = (data.get("choices") or [{}])[0] \
            .get("message", {}).get("content", "")
    except Exception as e:
        logger.warning("brain reply unreadable: %s", e)
        return []

    obj = _extract_json(content)
    if not obj:
        logger.warning("brain reply was not JSON: %s", str(content)[:200])
        return []

    allowed_set = set(allowed)
    plans: List[Dict[str, Any]] = []
    seen = set()

    def add(entry: Dict[str, Any], primary: bool) -> None:
        tech = str(entry.get("technique") or "").strip()
        target = str(entry.get("target") or "").strip()
        if tech not in allowed_set:
            logger.warning("brain proposed unknown technique %r — rejected",
                           tech)
            return
        if hosts and target not in hosts:
            logger.warning("brain proposed unknown target %r — rejected",
                           target)
            return
        if (tech, target) in seen:
            return
        seen.add((tech, target))
        try:
            conf = float(entry.get("confidence")
                         if entry.get("confidence") is not None
                         else (obj.get("confidence") if primary else 0.0))
        except (TypeError, ValueError):
            conf = 0.0
        conf = max(0.0, min(1.0, conf))
        hyp = (entry.get("hypothesis") or
               (obj.get("hypothesis") if primary else "") or "")
        plans.append({
            "technique": tech,
            "target": target,
            "hypothesis": str(hyp)[:500],
            "skip": ([str(k) for k in (obj.get("skip") or [])][:10]
                     if primary else []),
            "confidence": conf,
            "model": s["model"],
        })

    add({**(obj.get("next") or {}),
         "confidence": obj.get("confidence"),
         "hypothesis": obj.get("hypothesis")}, True)
    for alt in (obj.get("alternatives") or [])[:2]:
        if isinstance(alt, dict):
            add(alt, False)
    return plans


def hypothesize(brief: Dict[str, Any],
                timeout: float = 60.0) -> Optional[Dict[str, Any]]:
    """Back-compat single-plan view of :func:`hypothesize_options`."""
    opts = hypothesize_options(brief, timeout)
    return opts[0] if opts else None
