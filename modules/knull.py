"""autonomous_agent.py — Autonomous Hacking Agent.

The "active intelligence" that takes the helm after domain selection.
Runs a continuous decision loop:

  RECON → ANALYZE → DECIDE → EXECUTE → VERIFY → ADAPT → NEXT

Uses all existing modules as "tools" the agent can invoke:
  - attack_advisor: decides WHAT to attack next
  - kill_chain: builds HOW to attack (exploit + payload + listener)
  - waf_evasion: adapts when WAF blocks
  - credential harvester results → cred_engine → lateral movement
  - session_interceptor: post-exploitation playbook

Agent publishes events via callback for SSE live dashboard feed.
"""
from __future__ import annotations

import json
import logging
import re
import secrets
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("AttackSurface.Knull")

KALI_CONTAINER = "kali-as"

# Port → service name, used by the live recon probe so the advisor sees
# the same shape of data it gets from a full port scan.
_PORT_SERVICES = {
    21: "ftp", 22: "ssh", 80: "http", 443: "https", 445: "microsoft-ds",
    3306: "mysql", 3389: "ms-wbt-server", 8080: "http-proxy",
}


def _guess_service(port: int) -> str:
    return _PORT_SERVICES.get(port, "unknown")


class AgentState(str, Enum):
    IDLE = "idle"
    RECON = "recon"
    ANALYZE = "analyze"
    DECIDE = "decide"
    EXECUTE = "execute"
    VERIFY = "verify"
    ADAPT = "adapt"
    DONE = "done"
    FAILED = "failed"
    PAUSED = "paused"


@dataclass
class AgentEvent:
    """A single event in the agent's decision log."""
    timestamp: str
    state: str
    action: str
    detail: str
    # None = no verdict yet (dry run, offline service, informational)
    success: Optional[bool] = True
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "state": self.state,
            "action": self.action,
            "detail": self.detail,
            "success": self.success,
            "data": self.data,
        }


@dataclass
class KillChainProgress:
    """Tracks kill chain phase completion."""
    phase: str
    status: str  # pending, running, success, failed, skipped
    detail: str = ""
    started_at: str = ""
    completed_at: str = ""


class Knull:
    """Knull — the autonomous hacking agent.

    After a domain is selected, the agent:
      1. Runs recon (reads scan data)
      2. Analyzes with advisor
      3. Decides best attack path
      4. Executes the attack command
      5. Verifies the result
      6. Adapts if failed (try alternative)
      7. Moves to next phase/target
    """

    KILL_CHAIN_PHASES = [
        "initial_access",
        "execution",
        "credential_access",
        "privilege_escalation",
        "persistence",
        "lateral_movement",
        "collection",
    ]

    def __init__(
        self,
        scan_id: int = 0,
        target_domain: str = "",
        max_iterations: int = 20,
        auto_execute: bool = False,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        db_path: Optional[str] = None,
        use_brain: bool = True,
        brain_timeout: float = 60.0,
        extra_scope: Optional[List[str]] = None,
        max_brain_calls: int = 5,
        brain_min_confidence: float = 0.5,
        brain_cooldown: float = 30.0,
        safe_verify: bool = True,
        campaign: bool = False,
    ):
        self.agent_id = secrets.token_hex(6)
        self.scan_id = scan_id
        self.target_domain = target_domain
        self.max_iterations = max_iterations
        self.auto_execute = auto_execute
        self.event_callback = event_callback
        self.db_path = db_path

        self.state = AgentState.IDLE
        self.events: List[AgentEvent] = []
        self.kill_chain: Dict[str, KillChainProgress] = {}
        self.iteration = 0
        self.current_target = ""
        self.current_technique = ""
        self.credentials_found: List[Dict[str, Any]] = []
        self.start_time = ""
        self._running = False
        self._live_hosts: List[Dict[str, Any]] = []
        # Attack-chain state: Knull walks one chain to its end before
        # falling back to the flat advisory ranking.
        self._chains: List[Dict[str, Any]] = []
        self._chain_idx = 0
        self._chain_step = 0
        # LLM reasoning layer — not a one-shot call: Knull re-asks after it
        # learns something, capped and rate-limited so cost stays bounded.
        self.use_brain = use_brain
        self.brain_timeout = brain_timeout
        self.max_brain_calls = max(0, int(max_brain_calls))
        self.brain_min_confidence = float(brain_min_confidence)
        self.brain_cooldown = float(brain_cooldown)
        self.safe_verify = bool(safe_verify)
        self._brain_plans: List[Dict[str, Any]] = []
        self._brain_idx = 0
        self._brain_calls = 0
        self._brain_last_ask = 0.0
        self._brain_asked = False       # kept for status/back-compat
        self._brain_spent = False
        self._outcomes_seen = 0
        self._brain_outcomes_at_ask = -1
        self._current_from_brain = False
        # Manual fire queue: commands prepared but left to the operator.
        self._fired: set = set()
        # ── Campaign mode ──────────────────────────────────────────────
        # In a campaign Knull works a whole estate instead of one domain:
        # every root scope becomes a leg, and a leg is closed only when it
        # yields nothing left to try. Per-leg state (tried moves, found
        # creds, foothold) is kept here so advancing does not throw away
        # what the previous leg proved.
        self.campaign = bool(campaign)
        self._campaign_legs: List[str] = []
        self._campaign_leg_idx = 0
        self._campaign_state: Dict[str, Dict[str, Any]] = {}
        self._remember_prefix = ""
        self._last_probe_output = ""
        # Engagement scope: only these roots (and hosts observed in the
        # scan) may ever be fired at, recorded against, or re-scanned.
        self.extra_scope: List[str] = [
            s.strip().lower().rstrip(".") for s in (extra_scope or [])]
        self._scope_hosts: set = set()

        # Initialize kill chain progress
        for phase in self.KILL_CHAIN_PHASES:
            self.kill_chain[phase] = KillChainProgress(phase=phase, status="pending")

    def _emit(self, state: str, action: str, detail: str,
              success: Optional[bool] = True,
              data: Optional[Dict[str, Any]] = None):
        """Emit an event to the log and callback."""
        event = AgentEvent(
            timestamp=time.strftime("%H:%M:%S"),
            state=state,
            action=action,
            detail=detail,
            success=success,
            data=data or {},
        )
        self.events.append(event)
        logger.info("[Agent %s] [%s] %s: %s", self.agent_id[:6], state, action, detail)
        if self.event_callback:
            try:
                self.event_callback(event.to_dict())
            except Exception:
                pass

    def _set_state(self, new_state: AgentState, detail: str = ""):
        """Transition to a new state."""
        old_state = self.state
        self.state = new_state
        self._emit(new_state.value, "state_change",
                   f"{old_state.value} → {new_state.value}" + (f": {detail}" if detail else ""))

    def get_status(self) -> Dict[str, Any]:
        """Return current agent status for dashboard."""
        return {
            "agent_id": self.agent_id,
            "state": self.state.value,
            "iteration": self.iteration,
            "max_iterations": self.max_iterations,
            "target": self.target_domain,
            "current_target": self.current_target,
            "current_technique": self.current_technique,
            "credentials_found": len(self.credentials_found),
            "running": self._running,
            "events": [e.to_dict() for e in self.events[-200:]],
            "prepared": self.prepared_commands(),
            "config": self.config(),
            "kill_chain": {
                phase: {"status": kp.status, "detail": kp.detail}
                for phase, kp in self.kill_chain.items()
            },
            "campaign": self.campaign_state(),
        }

    def start(self) -> Dict[str, Any]:
        """Start the agent decision loop."""
        self._running = True
        self.start_time = time.strftime("%Y-%m-%d %H:%M:%S")
        self._set_state(AgentState.IDLE, "Agent started")
        try:
            self._run_loop()
        except Exception as e:
            self._emit("error", "agent_crash", str(e), success=False)
            self._set_state(AgentState.FAILED, str(e))
        self._running = False
        return self.get_status()

    def stop(self):
        """Stop the agent."""
        self._running = False
        self._emit("idle", "agent_stopped", "Operator stopped the agent")
        self._persist_run()

    def _run_loop(self):
        """Main decision loop."""
        if self.campaign and not self._campaign_legs:
            self._campaign_begin()
        for self.iteration in range(1, self.max_iterations + 1):
            if not self._running:
                break

            self._emit("loop", "iteration_start",
                       f"Iteration {self.iteration}/{self.max_iterations}")

            # PHASE 1: Recon
            self._set_state(AgentState.RECON)
            scan_data = self._recon()
            if not scan_data:
                self._emit("recon", "no_data", "No scan data available", success=False)
                break

            # PHASE 2: Analyze
            self._set_state(AgentState.ANALYZE)
            analysis = self._analyze(scan_data)
            if not analysis or not analysis.get("execution_order"):
                self._emit("analyze", "no_paths", "No attack paths found")
                # Campaign: a drained leg is not the end of the engagement
                # — close it and advance. Non-campaign runs keep the old
                # behaviour (enrich from a sibling scan, then stop).
                if self.campaign:
                    # Enrich first (live recon, sibling scan) — a leg can be
                    # drained only of *stored* data while the host still
                    # answers. Do it at most once per leg, or the loop burns
                    # every remaining iteration on the same empty target.
                    if self._campaign_leg_enriched():
                        continue
                    if self._campaign_advance():
                        continue
                    self._set_state(AgentState.DONE,
                                    "Campaign finished — every leg worked")
                    break
                # Try alternative scan data
                if not self._try_alternative_scan():
                    self._set_state(AgentState.DONE, "No more targets to analyze")
                    break
                continue

            # PHASE 3: Decide
            self._set_state(AgentState.DECIDE)
            target = self._decide(analysis)
            if not target:
                self._emit("decide", "no_target", "No viable target selected")
                # "No viable target" means every move on THIS leg is either
                # tried or memory-blocked — that is a drained leg, and it is
                # the campaign's cue to advance. `continue` here instead
                # burned every remaining iteration on the same leg.
                if self.campaign and self._campaign_advance():
                    continue
                if self.campaign:
                    self._set_state(AgentState.DONE,
                                    "Campaign finished — every leg worked")
                    break
                continue

            # PHASE 4: Execute
            self._set_state(AgentState.EXECUTE)
            result = self._execute(target)

            # PHASE 5: Verify
            self._set_state(AgentState.VERIFY)
            verified = self._verify(result)

            # PHASE 6: Adapt — None means dry run: nothing was proven, so
            # don't claim success and don't burn the path as "attempted".
            self._set_state(AgentState.ADAPT)
            if verified is True:
                self._on_success(target, result)
            elif verified is False:
                self._on_failure(target, result)
            else:
                self._emit("adapt", "dry_run_pending",
                           f"{target.get('technique', '')} prepared but not "
                           f"executed — enable auto-execute to run it",
                           success=None)
                # A prepared-but-unrun command teaches Knull nothing about
                # success, but recording it lets the panel show the attempt.
                self._remember(target, "pending", detail="dry run")

        # Final state
        if self._running:
            self._set_state(AgentState.DONE,
                            f"Completed {self.iteration} iterations")
        self._persist_run()

    def _persist_run(self) -> None:
        """Write this session to disk so the history survives a restart.

        The in-memory _agent_instance is dropped the moment the dashboard
        restarts; without this, every decision, hypothesis and chain walk
        would vanish from the panel, the chat context and the operator's
        ability to review what Knull did.
        """
        try:
            import db_store
            decided = [e.data.get("target_key", "") for e in self.events
                       if e.action in ("brain_step", "chain_step",
                                       "target_selected")
                       and e.data.get("target_key")]
            state = self.state
            db_store.save_knull_run({
                "agent_id": self.agent_id,
                "ts_start": self.start_time,
                "ts_end": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "domain": self.target_domain,
                "scan_id": self.scan_id,
                "state": state.value if isinstance(state, Enum)
                         else str(state),
                "iteration": self.iteration,
                "max_iterations": self.max_iterations,
                "brain_calls": self._brain_calls,
                "prepared": len(self.prepared_commands()),
                "fired": len(self._fired),
                "credentials": len(self.credentials_found),
                "kill_chain": {k: {"status": v.status, "detail": v.detail}
                               for k, v in self.kill_chain.items()},
                "moves": decided,
                "events": [e.to_dict() for e in self.events[-200:]],
            }, db_path=self.db_path)
        except Exception as e:  # history must never break a run
            logger.warning("knull run persist failed: %s", e)

    def _recon(self) -> Dict[str, Any]:
        """Phase 1: Read scan data and identify attack surface."""
        try:
            import db_store
            if self.scan_id:
                data = db_store.get_scan(self.scan_id, self.db_path)
            else:
                # Find latest scan for target domain
                scans = db_store.list_scans(self.db_path)
                for s in scans:
                    if s.get("domain") == self.target_domain:
                        data = db_store.get_scan(s["id"], self.db_path)
                        self.scan_id = s["id"]
                        break
                else:
                    data = {}

            # Backfill the target domain when the caller only supplied a
            # scan_id (the dashboard's "Launch Agent" path does). Without
            # this, memory rows are written with domain='' and never count
            # towards that domain's learning.
            if data and not self.target_domain:
                dom = str(data.get("domain") or "").strip().lower()
                if dom:
                    self.target_domain = dom
                    self._emit("recon", "domain_backfilled",
                               f"target domain set from scan: {dom}")

            # Merge live probe results so the advisor sees real service flags.
            if self._live_hosts:
                merged = list(data.get("hosts") or [])
                known = {h.get("host") for h in merged if isinstance(h, dict)}
                for h in self._live_hosts:
                    if h["host"] not in known:
                        merged.append(h)
                data["hosts"] = merged
                self._emit("recon", "live_merge",
                           f"Merged {len(self._live_hosts)} live host(s) into scan data",
                           data={"live_hosts": len(self._live_hosts)})

            hosts = data.get("hosts", [])
            findings = data.get("findings", [])

            # Scope cache: every host/IP the scan actually saw is in bounds.
            for h in hosts:
                if not isinstance(h, dict):
                    continue
                for key in ("host", "ip"):
                    v = (h.get(key) or "").strip().lower()
                    if v:
                        self._scope_hosts.add(v)
            for s in (data.get("subdomains") or []):
                if isinstance(s, str) and s.strip():
                    self._scope_hosts.add(s.strip().lower())

            # Engagement state for the advisor: phases 3-7 must only score
            # against proof this run actually produced. A verified foothold
            # is the execution phase having gone to success (shell/session
            # evidence in _on_success), and held credentials are the
            # harvested list — never an assumption from the scan data.
            #
            # msf_module_present is real evidence too, and it comes from the
            # scan: an MSF suggestion row means a module was resolved for a
            # service we saw. Without setting it here the advisor's
            # CVE->MSF pipeline was dead code — the same dead-flag mistake
            # as --asm. msf_hosts is host-level so only the hosts that
            # actually have a resolved module get the exploit step.
            msf_rows = [r for s in
                        (data.get("sections") or {}).get("msf_suggestions") or []
                        for r in [s] if isinstance(s, dict)]
            exec_phase = self.kill_chain.get("execution")
            data["_engagement"] = {
                "foothold": bool(exec_phase and exec_phase.status == "success"),
                "creds": len(self.credentials_found),
                "msf_module_present": bool(msf_rows),
                "msf_hosts": sorted({str(r.get("host") or "") for r in msf_rows}
                                    - {""}),
            }

            self._emit("recon", "scan_loaded",
                       f"Scan #{self.scan_id}: {len(hosts)} hosts, {len(findings)} findings",
                       data={"hosts": len(hosts), "findings": len(findings)})
            return data
        except Exception as e:
            self._emit("recon", "error", str(e), success=False)
            return {}

    def _analyze(self, scan_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Phase 2: Run attack advisor analysis + build attack chains."""
        try:
            from modules.attack_advisor import recommend_attacks
            result = recommend_attacks(scan_data)
            paths = result.get("execution_order", [])
            self._emit("analyze", "advisor_result",
                       f"{len(paths)} attack paths identified",
                       data={"paths": len(paths)})
        except Exception as e:
            self._emit("analyze", "error", str(e), success=False)
            return None

        # Multi-hop chains: Knull prefers walking one chain end-to-end over
        # jumping between unrelated single techniques.
        try:
            from modules.attack_graph import find_chains
            chains = find_chains(scan_data) or []
            if chains and not self._chains:
                self._chains = chains
                best = chains[0]
                self._emit("analyze", "chains_found",
                           f"{len(chains)} chain(s); best: " +
                           " → ".join(s["technique"] for s in best["steps"]) +
                           f" [{best.get('confidence')}, "
                           f"{best['probability']*100:.1f}%]",
                           data={"chains": len(chains),
                                 "best": best.get("id")})
            elif not chains:
                self._emit("analyze", "no_chains",
                           "no linkable chain — using single techniques")
        except Exception as e:
            self._emit("analyze", "chain_error", str(e), success=False)

        self._ask_brain(scan_data)
        return result

    def _brain_brief(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Structured evidence pack for the LLM (no secrets, no commands)."""
        import json as _json

        def jp(v: Any) -> Any:
            if isinstance(v, str):
                try:
                    return _json.loads(v)
                except (ValueError, TypeError):
                    return []
            return v or []

        hosts: List[Dict[str, Any]] = []
        for h in (scan_data.get("hosts") or []):
            ports = []
            for p in (jp(h.get("ports")) if isinstance(jp(h.get("ports")), list)
                      else []):
                if isinstance(p, dict):
                    ports.append(p.get("port"))
                elif isinstance(p, int):
                    ports.append(p)
            if h.get("host"):
                hosts.append({"host": h["host"], "ports": ports})
        if not hosts:
            hosts = [{"host": s, "ports": []}
                     for s in (scan_data.get("subdomains") or [])[:40]
                     if isinstance(s, str)]

        findings = [f"{f.get('host', '?')}: {str(f.get('title', ''))[:80]}"
                    for f in (scan_data.get("findings") or [])
                    if isinstance(f, dict)]
        stats = self._memory_stats()
        memory = {k: f"{v.get('success', 0)} success / "
                    f"{v.get('failure', 0)} failure"
                  for k, v in stats.items()}
        tried = [e.data.get("target_key", "") for e in self.events
                 if e.data.get("target_key")]
        try:
            from modules.attack_advisor import ATTACK_TECHNIQUES
            techniques = list(ATTACK_TECHNIQUES)
        except Exception:
            techniques = []

        # What the brain itself proposed before, and how it turned out —
        # the only way it can stop repeating a refuted idea.
        brain_history: List[str] = []
        brain_sessions: List[str] = []
        try:
            import db_store
            for row in db_store.knull_memory(
                    limit=60,
                    domain=self.target_domain or None,
                    db_path=self.db_path):
                detail = str(row.get("detail") or "")
                if detail.startswith("[brain]"):
                    brain_history.append(
                        f"{row.get('technique')} on {row.get('target')} "
                        f"-> {row.get('outcome')}: {detail[:80]}")
                else:
                    # Cross-run session memory: what the brain proposed in
                    # an earlier run, and how that proposal aged.
                    brain_sessions.append(
                        f"{row.get('technique')} on {row.get('target')} "
                        f"-> {row.get('outcome')}: {detail[:80]}")
        except Exception:
            pass

        return {
            "domain": self.target_domain or scan_data.get("domain", ""),
            "hosts": hosts,
            "findings": findings,
            "kill_chain": {k: v.status for k, v in self.kill_chain.items()},
            "memory": memory,
            "tried": tried,
            "chains": self._chains,
            "techniques": techniques,
            "brain_history": brain_history,
            "brain_sessions": brain_sessions,
            "credentials_held": len(self.credentials_found),
        }

    def _ask_brain(self, scan_data: Dict[str, Any]) -> None:
        """Ask the LLM for hypotheses — and re-ask as Knull learns.

        The brain used to be asked exactly once per run, so it never found
        out whether its pick worked. It now re-asks, but only when
        something actually happened since the last call (``_outcomes_seen``
        moved), the cooldown passed, and the per-run budget allows it —
        blind re-asking every iteration would be slow and expensive.
        """
        if not self.use_brain or self.max_brain_calls <= 0:
            return
        if self._brain_calls >= self.max_brain_calls:
            return
        now = time.time()
        if self._brain_calls:
            if (now - self._brain_last_ask) < self.brain_cooldown:
                return
            if self._outcomes_seen <= self._brain_outcomes_at_ask:
                return  # nothing new has been learned since the last answer
        self._brain_calls += 1
        self._brain_last_ask = now
        self._brain_outcomes_at_ask = self._outcomes_seen
        self._brain_asked = True
        try:
            from modules import knull_brain
            if not knull_brain.available(timeout=8.0):
                if self._brain_calls == 1:
                    self._emit("analyze", "brain_offline",
                               "no LLM endpoint — using advisor ranking",
                               success=None)
                return
            plans = knull_brain.hypothesize_options(
                self._brain_brief(scan_data),
                timeout=self.brain_timeout)
            if plans:
                self._brain_plans = plans
                self._brain_idx = 0
                self._brain_spent = False
                lead = plans[0]
                self._emit(
                    "analyze", "brain_hypothesis",
                    f"brain #{self._brain_calls}/{self.max_brain_calls}: "
                    f"{lead['technique']} on {lead['target']} "
                    f"(confidence {lead['confidence']:.2f}, "
                    f"{len(plans)} option(s)) — {lead['hypothesis'][:180]}",
                    data={"plan": lead, "call": self._brain_calls,
                          "options": len(plans)})
            else:
                self._emit("analyze", "brain_rejected",
                           "brain returned nothing valid — using advisor "
                           "ranking", success=None)
        except Exception as e:
            self._emit("analyze", "brain_error", str(e), success=False)

    def _next_brain_step(self, paths: List[Dict[str, Any]]
                         ) -> Optional[Dict[str, Any]]:
        """Take the first brain option that is confident, viable, untried.

        Three gates protect the loop:
          * confidence >= brain_min_confidence — a hesitant guess must not
            override the chain's structured plan;
          * the advisor must score it — the brain may only choose moves we
            know how to run (an unviable pick has no path entry);
          * it must not already be attempted — dedup by display name, the
            same key every other path emits, or brain and chain could run
            the same move twice.
        """
        if not self._brain_plans or self._brain_spent:
            return None
        attempted = {e.data.get("target_key", "") for e in self.events}
        rejected_low = 0
        for plan in self._brain_plans:
            conf = float(plan.get("confidence") or 0.0)
            if conf < self.brain_min_confidence:
                rejected_low += 1
                continue
            match = next(
                (p for p in paths
                 if p.get("technique_key") == plan.get("technique")
                 and p.get("target") == plan.get("target")), None)
            if match is None:
                continue
            key = f"{match.get('target', '')}:{match.get('technique', '')}"
            if key in attempted:
                continue
            self._brain_spent = True
            self.current_target = match.get("target", "")
            self.current_technique = match.get("technique", "")
            self._current_from_brain = True
            self._emit("decide", "brain_step",
                       f"brain chose {match.get('technique')} on "
                       f"{match.get('target')} "
                       f"(confidence {conf:.2f})",
                       data={"target_key": key, "path": match,
                             "hypothesis": plan.get("hypothesis", "")})
            return match

        self._brain_spent = True
        if rejected_low:
            self._emit("decide", "brain_low_confidence",
                       f"{rejected_low} brain option(s) below "
                       f"confidence {self.brain_min_confidence:.2f} — "
                       f"deferring to the chain/advisor",
                       success=None)
        else:
            self._emit("decide", "brain_unviable",
                       "no brain option the advisor scores as viable — "
                       "deferring to the chain/advisor", success=None)
        return None

    def _next_chain_step(self) -> Optional[Dict[str, Any]]:
        """Next untried step of the active chain, or None to fall back."""
        if not self._chains:
            return None
        stats = self._memory_stats()
        failed = {t for t, st in stats.items()
                  if st.get("failure") and not st.get("success")}
        attempted = {e.data.get("target_key", "") for e in self.events}

        while self._chain_idx < len(self._chains):
            chain = self._chains[self._chain_idx]
            steps = chain.get("steps") or []
            if any(s.get("technique") in failed for s in steps):
                # memory says a step of this chain already failed here
                self._chain_idx += 1
                self._chain_step = 0
                continue
            while self._chain_step < len(steps):
                step = steps[self._chain_step]
                key = f"{step.get('target','')}:{step.get('technique','')}"
                if key in attempted:
                    self._chain_step += 1
                    continue
                self.current_target = step.get("target", "")
                self.current_technique = step.get("technique", "")
                self._emit("decide", "chain_step",
                           f"chain {self._chain_idx + 1}/{len(self._chains)} "
                           f"step {step.get('n', self._chain_step + 1)}/"
                           f"{len(steps)}: {step.get('technique')} on "
                           f"{step.get('target')} "
                           f"[{chain.get('confidence')}]",
                           data={"target_key": key, "path": step,
                                 "chain_id": chain.get("id"),
                                 "chain_confidence": chain.get("confidence")})
                return step
            self._chain_idx += 1
            self._chain_step = 0
        return None

    def _decide(self, analysis: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Phase 3: Select the best attack target and technique.

        Knull's long-term memory adjusts the decision:
          - a technique that failed before on this domain is skipped
            (unless nothing else is available),
          - a technique with prior successes gets its score boosted.
        """
        paths = analysis.get("execution_order", [])
        if not paths:
            return None

        # Decision order:
        #   1. the LLM hypothesis (consumed at most once per run),
        #   2. the active attack chain (walked step by step),
        #   3. the flat advisor ranking, adjusted by long-term memory.
        self._current_from_brain = False
        brain_step = self._next_brain_step(paths)
        if brain_step:
            return brain_step

        chain_step = self._next_chain_step()
        if chain_step:
            return chain_step

        stats = self._memory_stats()
        if stats:
            self._emit("decide", "memory_loaded",
                       f"Memory: {len(stats)} technique(s) with history",
                       data={"stats": stats})

        def adjusted(path: Dict[str, Any]) -> float:
            st = stats.get(path.get("technique", ""), {})
            score = float(path.get("score", 0) or 0)
            # Prior success raises the score; prior failure lowers it.
            if st.get("success"):
                score *= 1.0 + min(0.5, 0.25 * st["success"])
            if st.get("failure"):
                score *= max(0.3, 1.0 - 0.35 * st["failure"])
            # Holding harvested credentials makes reuse techniques stronger.
            if (self.credentials_found
                    and path.get("technique_key") in self._CRED_REUSE):
                score *= 1.25
            return score

        ranked = sorted(paths, key=adjusted, reverse=True)
        failed_before = {t for t, st in stats.items()
                         if st.get("failure") and not st.get("success")}
        skipped = 0

        # Pick the highest-score path that hasn't been tried yet
        for path in ranked:
            technique = path.get("technique", "")
            if technique in failed_before and len(ranked) > 1:
                skipped += 1
                continue
            target_key = f"{path['target']}:{technique}"
            if target_key not in [e.data.get("target_key", "") for e in self.events]:
                self.current_target = path.get("target", "")
                self.current_technique = technique
                adj = adjusted(path)
                note = f"adjusted score: {adj:.1f}" if adj != path.get("score") else \
                       f"score: {path['score']}"
                if skipped:
                    note += f" (skipped {skipped} failed-before technique(s))"
                self._emit("decide", "target_selected",
                           f"{technique} on {path['target']} "
                           f"({note}, prob: {path['probability']*100:.0f}%)",
                           data={"target_key": target_key, "path": path,
                                 "adjusted_score": adj})
                return path

        self._emit("decide", "all_tried", "All paths already attempted")
        return None

    def _memory_stats(self) -> Dict[str, Any]:
        """Per-technique history for the target domain (empty on error)."""
        try:
            import db_store
            return db_store.knull_stats(domain=self.target_domain,
                                        db_path=self.db_path)
        except Exception:
            return {}

    def _remember(self, target: Dict[str, Any], outcome: str,
                  detail: str = "") -> None:
        """Persist an attempt outcome into Knull's long-term memory."""
        # Any new outcome is information the brain should react to — counted
        # outside the try so a DB failure cannot silently freeze learning.
        self._outcomes_seen += 1
        try:
            import db_store
            if self._current_from_brain and "brain" not in detail:
                detail = f"[brain] {detail}"
            if self._remember_prefix:
                detail = f"{self._remember_prefix}{detail}"
            db_store.knull_remember(
                technique=target.get("technique", ""),
                outcome=outcome,
                domain=self.target_domain,
                target=target.get("target", ""),
                score=target.get("score"),
                detail=detail or target.get("command", "")[:200],
                db_path=self.db_path,
            )
        except Exception as e:  # memory must never break the loop
            logger.warning("knull memory write failed: %s", e)

    # Runtime settings the operator may change while a session runs.
    _NUMERIC_LIMITS = {
        "brain_min_confidence": (0.0, 1.0),
        "max_brain_calls": (0, 10),
        "brain_cooldown": (0.0, 3600.0),
        "max_iterations": (1, 50),
    }
    _BOOL_SETTINGS = ("use_brain", "safe_verify", "campaign")

    def config(self) -> Dict[str, Any]:
        """Effective settings — what the operator can see and change."""
        return {
            "use_brain": self.use_brain,
            "safe_verify": self.safe_verify,
            "auto_execute": self.auto_execute,
            "campaign": self.campaign,
            "brain_min_confidence": self.brain_min_confidence,
            "max_brain_calls": self.max_brain_calls,
            "brain_cooldown": self.brain_cooldown,
            "max_iterations": self.max_iterations,
            "extra_scope": list(self.extra_scope),
        }

    def configure(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Apply validated runtime settings; returns what took effect.

        Values are clamped and typed server-side: the console is a
        convenience, never a way to hand Knull something it cannot hold.
        """
        applied: Dict[str, Any] = {}
        errors: List[str] = []
        for key, raw in (updates or {}).items():
            if key == "extra_scope":
                if isinstance(raw, str):
                    roots = [s.strip() for s in raw.split(",") if s.strip()]
                elif isinstance(raw, (list, tuple)):
                    roots = [str(s).strip() for s in raw if str(s).strip()]
                else:
                    errors.append("extra_scope must be a list of domains")
                    continue
                self.extra_scope = [r.lower().rstrip(".") for r in roots]
                applied["extra_scope"] = list(self.extra_scope)
                continue
            if key in self._BOOL_SETTINGS:
                if not isinstance(raw, bool):
                    errors.append(f"{key} must be true/false")
                    continue
                setattr(self, key, raw)
                applied[key] = raw
                continue
            if key in self._NUMERIC_LIMITS:
                lo, hi = self._NUMERIC_LIMITS[key]
                try:
                    val = float(raw)
                except (TypeError, ValueError):
                    errors.append(f"{key} must be a number")
                    continue
                val = max(lo, min(hi, val))
                if key in ("max_brain_calls", "max_iterations"):
                    val = int(val)
                setattr(self, key, val)
                applied[key] = val
                continue
            errors.append(f"unknown setting: {key}")
        if applied:
            self._emit("config", "config_changed",
                       "settings updated: " + ", ".join(
                           f"{k}={v}" for k, v in applied.items()))
        return {"ok": not errors, "applied": applied, "errors": errors,
                "config": self.config()}

    def _store_evidence(self, target: Dict[str, Any], outcome: str,
                        command: str = "", output: str = "",
                        exit_code: Optional[int] = None,
                        source: str = "") -> None:
        """Keep the raw proof behind one verdict.

        Findings without evidence are opinions; this is what lets the
        operator ask 'show me the proof' and get the actual response.
        """
        if not (output or exit_code is not None):
            return
        try:
            import db_store
            db_store.save_evidence({
                "agent_id": self.agent_id,
                "domain": self.target_domain,
                "technique": target.get("technique", ""),
                "target": target.get("target", ""),
                "source": source,
                "outcome": outcome,
                "command": command or target.get("command", ""),
                "exit_code": exit_code,
                "output": output,
            }, db_path=self.db_path)
        except Exception as e:  # evidence must never break a run
            logger.warning("knull evidence write failed: %s", e)

    def _probe_ftp_anonymous(self, host: str) -> Optional[bool]:
        """Read-only anonymous-FTP LIST: does the claim actually hold?

        LIST only — no STOR/DELE, nothing is written to the target.
        """
        cmd = ("curl -sS --max-time 12 --list-only "
               f"--user anonymous:anonymous@ ftp://{host}/")
        r = self._run_in_kali(cmd, timeout=25)
        self._last_probe_output = str(r.get("stdout") or "")[:4000]
        # NOTE: `r.get("exit_code", 1) or 1` would turn a successful exit 0
        # into 1 (0 is falsy), so the probe could never report success.
        raw = r.get("exit_code")
        try:
            code = int(raw)
        except (TypeError, ValueError):
            code = -1
        out = (r.get("stdout") or "").strip()
        if code == 0 and out:
            return True
        # 61 auth failed / 67 access denied / 63 login wrong — the service
        # answered and refused anonymous access: a real negative.
        if code in (61, 63, 67):
            return False
        return None

    def _probe_sqli(self, command: str) -> Optional[bool]:
        """Run the existing safe error-signature probe on the target URL."""
        m = re.search(r"https?://[^\s'\"]+", command or "")
        if not m:
            return None
        from modules.sqli_probe import _s, probe_url
        found = probe_url(m.group(0), _s())
        if isinstance(found, dict):
            self._last_probe_output = (
                f"probe on {found.get('url')} | params: "
                f"{', '.join(found.get('params') or [])} | db signatures: "
                f"{', '.join(found.get('db_signatures') or [])}")[:4000]
        else:
            self._last_probe_output = ""
        # True = a database error signature was disclosed (the claim holds)
        return bool(found)

    # Techniques whose claim can be tested WITHOUT running the attack.
    # ftp_anonymous (read-only LIST) and sqli (error-signature probe) are
    # passive; the post-exploitation moves (sudo_check, ssh_persist, cred_reuse,
    # msf_exploit, db_enum) have read-only pre-checks that only need the
    # target to answer — they never write, they only ask.
    _SAFE_CHECKABLE = {"ftp_anonymous", "sqli"}

    def _safe_verify(self, target: Dict[str, Any]) -> Optional[bool]:
        """Passively check whether this technique's claim holds.

        Returns True/False when a read-only probe answers, and None when
        the claim can only be settled by actually attacking (brute force,
        RCE, credential reuse). This is what turns a dry run into a real
        verdict: without it every memory row stayed 'pending' — 95 of
        them — so the scoreboard, the worn-out list and the brain's
        feedback loop could never learn anything.
        """
        key = target.get("technique_key") or ""
        host = target.get("target") or ""
        if not host or key not in self._SAFE_CHECKABLE:
            return None
        if not self._in_scope(host):
            self._emit("execute", "verify_blocked",
                       self._scope_error(host), success=False)
            return None
        try:
            if key == "ftp_anonymous":
                return self._probe_ftp_anonymous(host)
            if key == "sqli":
                return self._probe_sqli(target.get("command") or "")
            if key == "sudo_check":
                # Read-only sudo -n -l: asks, writes nothing, never escalates.
                cmd = f"ssh {host} 'sudo -n -l'"
                r = self._run_in_kali(cmd, timeout=30)
                self._last_probe_output = str(r.get("stdout") or "")
                raw = r.get("exit_code")
                try:
                    code = int(raw)
                except (TypeError, ValueError):
                    code = -1
                out = (r.get("stdout") or "").strip()
                if code == 0 and out:
                    return True
                return False
            if key == "db_enum":
                # Read-only mysql show databases.
                cmd = (f"mysql -h {host} -u root --connect-timeout=8 "
                       "-e 'show databases;'")
                r = self._run_in_kali(cmd, timeout=30)
                self._last_probe_output = str(r.get("stdout") or "")
                raw = r.get("exit_code")
                try:
                    code = int(raw)
                except (TypeError, ValueError):
                    code = -1
                out = (r.get("stdout") or "").strip()
                if code == 0 and out:
                    return True
                return False
            return None
        except Exception as e:
            self._emit("execute", "safe_verify_error", str(e), success=False)
            return None

    def _execute(self, target: Dict[str, Any],
                 force: bool = False) -> Dict[str, Any]:
        """Phase 4: Execute the attack command.

        ``force=True`` is the operator's manual fire: it runs the stored
        command even when the autonomous loop is in dry-run mode.
        """
        # Reset the record tag: a previous dry-run's "[verify]" must not
        # leak into this attempt's memory row.
        self._remember_prefix = ""
        self._last_probe_output = ""
        command = target.get("command", "")
        technique = target.get("technique", "")
        target_host = target.get("target", "")

        self._emit("execute", "command_prepared",
                   f"Command: {command[:100]}...",
                   data={"command": command, "technique": technique,
                         "target": target_host,
                         "target_key": f"{target_host}:{technique}"})

        if not self.auto_execute and not force:
            self._emit("execute", "dry_run",
                       "DRY RUN — command not executed (auto_execute=False)")
            verdict = self._safe_verify(target) if self.safe_verify else None
            if verdict is None:
                # Distinguish "no checker exists" from "the checker ran but
                # could not get an answer" — both stay pending, but only
                # the second one means the target stopped responding.
                if (target.get("technique_key") in self._SAFE_CHECKABLE):
                    msg = ("non-destructive probe inconclusive (no answer "
                           "from the target) — outcome stays pending")
                else:
                    msg = ("no non-destructive check exists for this "
                           "technique — outcome stays pending")
                self._emit("execute", "safe_probe_skipped", msg, success=None)
                self._store_evidence(target, "no_verdict", command=command,
                                     output=self._last_probe_output,
                                     source="verify")
                return {"command": command, "executed": False, "output": "",
                        "technique": technique, "target": target_host}
            # Tag the record so the scoreboard can separate passive
            # verification from a real (operator-fired) shot.
            self._remember_prefix = "[verify] "
            verdict_text = ("claim confirmed" if verdict else
                            "no evidence — claim not supported")
            self._emit("execute", "safe_probe",
                       f"non-destructive check on {target_host}: {verdict_text}",
                       success=verdict)
            self._store_evidence(
                target, "confirmed" if verdict else "not_supported",
                command=command, output=self._last_probe_output,
                source="verify")
            return {"command": command, "executed": False, "output": "",
                    "safe_verdict": verdict, "technique": technique,
                    "target": target_host}

        # Execute in kali-as container
        try:
            result = self._run_in_kali(command, timeout=60)
            success = result.get("exit_code", 1) == 0
            self._emit("execute", "command_executed",
                       f"Exit code: {result.get('exit_code', 'N/A')}, "
                       f"Output: {result.get('stdout', '')[:200]}",
                       success=success,
                       data={"exit_code": result.get("exit_code"),
                             "stdout": result.get("stdout", "")[:2000],
                             "stderr": result.get("stderr", "")[:500]})
            self._store_evidence(
                target, "executed" if success else "executed_failed",
                command=command,
                output=((result.get("stdout") or "") + "\n" +
                        (result.get("stderr") or ""))[:4000],
                exit_code=result.get("exit_code"),
                source="fired" if force else "auto")
            return {"command": command, "executed": True,
                    "output": result.get("stdout", ""),
                    "exit_code": result.get("exit_code"),
                    "success": success,
                    "technique": technique, "target": target_host}
        except Exception as e:
            self._emit("execute", "error", str(e), success=False)
            self._store_evidence(target, "error", command=command,
                                 output=str(e)[:2000], source="fired")
            return {"command": command, "executed": False, "error": str(e),
                    "success": False, "technique": technique, "target": target_host}

    def prepared_commands(self) -> List[Dict[str, Any]]:
        """Commands Knull prepared but did not run — the manual fire queue."""
        out: List[Dict[str, Any]] = []
        seen = set()
        for e in self.events:
            if e.action != "command_prepared":
                continue
            tk = (e.data.get("target_key")
                  or f"{e.data.get('target', '')}:"
                     f"{e.data.get('technique', '')}")
            if tk in seen:
                continue
            seen.add(tk)
            out.append({
                "target_key": tk,
                "technique": e.data.get("technique", ""),
                "target": e.data.get("target", ""),
                "command": e.data.get("command", ""),
                "fired": tk in self._fired,
            })
        return out

    @staticmethod
    def _host_of(value: str) -> str:
        """Host part of a URL / host:port / bare-host string, lowercased."""
        v = (value or "").strip().lower()
        if not v:
            return ""
        if "://" in v:
            v = v.split("://", 1)[1]
        v = v.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in v:
            v = v.rsplit("@", 1)[-1]
        if v.startswith("["):
            v = v.split("]")[0].lstrip("[")
        elif ":" in v and v.count(":") == 1:
            v = v.split(":", 1)[0]
        return v.strip(". ")

    def scope_roots(self) -> List[str]:
        """Roots this engagement is authorized against."""
        roots = []
        if self.target_domain:
            roots.append(self.target_domain.strip().lower().rstrip("."))
        roots.extend(self.extra_scope)
        return [r for r in roots if r]

    def _in_scope(self, target: str) -> bool:
        """Is this host inside the authorized scope?

        A shot must never leave the engagement: subdomains of shared
        platforms (CDN, SaaS) or a typo'd host would otherwise be fair
        game for fire/record/impact. Hosts and IPs the scan itself saw
        are in bounds; everything else must be a subdomain of a scope root.
        """
        host = self._host_of(target)
        if not host:
            return False
        for root in self.scope_roots():
            if host == root or host.endswith("." + root):
                return True
        return host in self._scope_hosts

    def _scope_error(self, target: str) -> str:
        roots = ", ".join(self.scope_roots()) or "(none set)"
        return (f"target out of scope: {self._host_of(target) or target} "
                f"— allowed roots: {roots}")

    def _technique_key(self, display_name: str) -> str:
        """Map a display name ('SSH Brute Force') back to its key."""
        try:
            from modules.attack_advisor import ATTACK_TECHNIQUES
            rev = {(m.get("name") or k): k
                   for k, m in ATTACK_TECHNIQUES.items()}
            return rev.get((display_name or "").strip(), "")
        except Exception:
            return ""

    def record_attempt(self, technique: str, target: str, outcome: str,
                       output: str = "",
                       source: str = "operator") -> Dict[str, Any]:
        """Record a result the operator observed outside Knull.

        The operator may have run the command by hand in a terminal; this
        is how their verdict reaches long-term memory instead of
        evaporating. Success also advances the kill chain and harvests any
        credentials visible in ``output``.
        """
        outcome = (outcome or "").strip().lower()
        if outcome not in ("success", "failure", "pending"):
            return {"ok": False,
                    "error": "outcome must be success, failure or pending"}
        technique = (technique or "").strip()
        if not technique:
            return {"ok": False, "error": "technique required"}
        target = (target or "").strip()
        if target and not self._in_scope(target):
            return {"ok": False, "error": self._scope_error(target)}
        source = (source or "operator").strip() or "operator"

        t: Dict[str, Any] = {
            "technique": technique,
            "technique_key": self._technique_key(technique),
            "target": target,
            "command": "",
            "score": None,
        }
        self._remember_prefix = f"[{source}] "
        try:
            if outcome == "success":
                self._on_success(t, {"executed": True,
                                     "output": output or ""})
            elif outcome == "failure":
                self._on_failure(t, {"executed": True,
                                     "output": output or ""})
            else:
                self._remember(t, "pending", detail=technique)
        finally:
            self._remember_prefix = ""
        # keep whatever proof the operator pasted alongside the verdict
        self._store_evidence(t, outcome, output=output or "", source=source)

        self._emit("record", "operator_result",
                   f"{source}: {technique} on {target or '?'} → {outcome}",
                   success=(True if outcome == "success" else
                            False if outcome == "failure" else None),
                   data={"technique": technique, "target": target,
                         "outcome": outcome, "source": source})
        return {"ok": True, "outcome": outcome, "technique": technique,
                "kill_chain": {k: v.status for k, v in self.kill_chain.items()}}

    def record_impact(self, technique: str, target: str,
                      diff: Dict[str, Any]) -> Dict[str, Any]:
        """Store a before/after re-scan diff as evidence of real impact.

        A shot that changed nothing is recorded as a failure: the
        technique ran but moved no finding, which is exactly what the
        scoreboard needs in order to stop recommending it.
        """
        new_f = diff.get("new_findings") or []
        new_s = diff.get("new_subdomains") or []
        delta = diff.get("score_delta") or 0
        changed = bool(new_f) or bool(new_s) or bool(delta)
        summary = (f"findings {len(new_f)} new, "
                   f"subdomains {len(new_s)} new, risk Δ{delta:+g}")

        t: Dict[str, Any] = {"technique": technique or "?",
                             "technique_key": self._technique_key(technique or ""),
                             "target": target, "command": "", "score": None}
        self._remember_prefix = "[impact] "
        try:
            if changed:
                self._remember(t, "impact", detail=summary)
            else:
                self._remember(t, "failure", detail=f"no measurable change ({summary})")
        finally:
            self._remember_prefix = ""

        self._emit("impact", "impact_measured",
                   f"{technique} on {target or '?'} → "
                   f"{'IMPACT CONFIRMED' if changed else 'no change'} ({summary})",
                   success=changed,
                   data={"technique": technique, "target": target,
                         "changed": changed, "summary": summary})
        return {"ok": True, "changed": changed, "summary": summary,
                "diff": diff}

    def fire(self, target_key: str) -> Dict[str, Any]:
        """Run ONE prepared command — the operator picks which one.

        The client may only name a ``target_key``. The command string is
        always the one Knull itself prepared and stored, so this path can
        never be used to execute arbitrary shell supplied by the caller.
        """
        prepared = next((p for p in self.prepared_commands()
                         if p["target_key"] == target_key), None)
        if not prepared:
            return {"ok": False, "error": "no such prepared command"}
        if not self._in_scope(prepared["target"]):
            self._emit("execute", "fire_blocked",
                       self._scope_error(prepared["target"]), success=False,
                       data={"target_key": target_key,
                            "target": prepared["target"]})
            return {"ok": False,
                    "error": self._scope_error(prepared["target"])}
        if target_key in self._fired:
            return {"ok": False, "error": "already fired"}
        self._fired.add(target_key)

        self._emit("execute", "fire_requested",
                   f"operator fired {target_key}",
                   data={"target_key": target_key})

        target: Dict[str, Any] = {
            "technique": prepared["technique"],
            "target": prepared["target"],
            "command": prepared["command"],
            "score": None,
            "technique_key": self._technique_key(prepared["technique"]),
        }

        result = self._execute(target, force=True)
        verified = self._verify(result)
        self._remember_prefix = "[fired] "
        try:
            if verified is True:
                self._on_success(target, result)
            elif verified is False:
                self._on_failure(target, result)
            else:
                self._remember(target, "pending",
                               detail="fired, no verdict")
        finally:
            self._remember_prefix = ""

        self._emit("execute", "fire_result",
                   f"{target_key} → verified={verified}, "
                   f"exit={result.get('exit_code')}",
                   success=verified,
                   data={"target_key": target_key, "verified": verified})
        return {
            "ok": True,
            "verified": verified,
            "executed": result.get("executed"),
            "exit_code": result.get("exit_code"),
            "output": (result.get("output") or "")[:4000],
            "error": result.get("error"),
            "target_key": target_key,
            "technique": prepared["technique"],
        }

    def _verify(self, result: Dict[str, Any]) -> bool:
        """Phase 5: Verify the attack result.

        Three outcomes: True (verified), False (verified as not holding),
        None (no verdict — a dry run with no passive check available).
        """
        if not result.get("executed"):
            safe = result.get("safe_verdict")
            if safe is not None:
                self._emit("verify", "safe_verdict",
                           "verified by non-destructive probe: "
                           + ("claim holds" if safe else "claim not supported"),
                           success=bool(safe))
                return bool(safe)
            self._emit("verify", "not_executed",
                       "Command was not executed (dry run) — no verification possible",
                       success=None)
            return None

        output = result.get("output", "").lower()
        exit_code = result.get("exit_code", 1)

        # Success indicators
        success_indicators = [
            "anonymous", "welcome", "230", "login successful",
            "access granted", "shell", "meterpreter", "session opened",
            "uid=", "www-data", "root",
        ]
        failure_indicators = [
            "access denied", "login failed", "authentication failed",
            "permission denied", "connection refused", "timeout",
        ]

        has_success = any(ind in output for ind in success_indicators)
        has_failure = any(ind in output for ind in failure_indicators)

        verified = (exit_code == 0 and has_success and not has_failure)

        self._emit("verify", "result_verified",
                   f"Verified: {verified} (exit={exit_code}, "
                   f"success_match={has_success}, failure_match={has_failure})",
                   success=verified)
        return verified

    # Kill-chain phase each technique actually belongs to (MITRE view):
    # a successful SSH brute force is credential access, not initial access.
    _TECHNIQUE_PHASE = {
        "ftp_anonymous": "initial_access",
        "default_creds": "initial_access",
        "sqli": "initial_access",
        "cve_exploit": "initial_access",
        "subdomain_takeover": "initial_access",
        "xss": "initial_access",
        "ssh_brute": "credential_access",
        "ftp_brute": "credential_access",
        "rdp_brute": "credential_access",
        "mysql_brute": "credential_access",
        "smb_null_session": "credential_access",
        "ssh_key_auth": "credential_access",
        # Phases 4-7 — these only ever appear once Knull holds proof
        # (foothold_verified / creds_held), so planning them is evidence-
        # driven, not speculative.
        "sudo_check": "privilege_escalation",
        "ssh_persist": "persistence",
        "cred_reuse": "lateral_movement",
        # An MSF module matched against an exposed service is the same
        # move as cve_exploit — initial access, no foothold required.
        "msf_exploit": "initial_access",
        "db_enum": "collection",             # T1005 Data from Local System
    }

    # Techniques whose value rises once we hold candidate credentials.
    _CRED_REUSE = {"ssh_brute", "ftp_brute", "rdp_brute", "mysql_brute"}

    _CRED_PATTERNS = [
        re.compile(r"user(?:name)?\s*[:=]\s*(\S{1,64})\s*[,\s]+\s*"
                   r"pass(?:word|wd)?\s*[:=]\s*(\S{1,64})", re.I),
        re.compile(r"password\s+for\s+['\"]?(\S{1,64})['\"]?\s+is\s+"
                   r"['\"]?(\S{1,64})", re.I),
        re.compile(r"login successful[:=]?\s*(\S{1,64})\s*[:/]\s*(\S{1,64})",
                   re.I),
    ]

    def _harvest_credentials(self, output: str) -> List[Dict[str, str]]:
        """Pull candidate credentials out of command output.

        Conservative on purpose: only patterns with an explicit
        user/password shape are taken, so a wordlist line or an error
        message never becomes a "found credential".
        """
        if not output:
            return []
        found: List[Dict[str, str]] = []
        seen = set()
        for rx in self._CRED_PATTERNS:
            for m in rx.finditer(output):
                user, secret = m.group(1).strip("'\""), m.group(2).strip("'\"")
                key = (user, secret)
                if key in seen or not user or not secret:
                    continue
                seen.add(key)
                found.append({"username": user, "password": secret})
                if len(found) >= 20:
                    return found
        return found

    def _on_success(self, target: Dict[str, Any], result: Dict[str, Any]):
        """Handle successful attack — harvest and advance the kill chain."""
        technique = target.get("technique", "")
        tkey = target.get("technique_key", "")
        target_host = target.get("target", "")
        self._remember(target, "success", detail=f"{technique} on {target_host}")

        phase = self._TECHNIQUE_PHASE.get(tkey, "initial_access")
        if phase in self.kill_chain:
            self.kill_chain[phase].status = "success"
            self.kill_chain[phase].detail = f"{technique} on {target_host}"
            self.kill_chain[phase].completed_at = time.strftime("%H:%M:%S")

        # Real advancement: anything the output proves gets marked done,
        # and the next incomplete phase becomes the active one.
        output = result.get("output", "") or ""
        harvested = self._harvest_credentials(output)
        if harvested:
            self.credentials_found.extend(
                {**c, "source": technique, "host": target_host}
                for c in harvested
                if {c["username"], c["password"]} not in
                {(x.get("username"), x.get("password"))
                 for x in self.credentials_found})
            if "credential_access" in self.kill_chain:
                self.kill_chain["credential_access"].status = "success"
                self.kill_chain["credential_access"].detail = (
                    f"{len(self.credentials_found)} credential(s) from "
                    f"{technique}")
                self.kill_chain["credential_access"].completed_at = (
                    time.strftime("%H:%M:%S"))
            self._emit("success", "credentials_harvested",
                       f"{len(harvested)} credential candidate(s) from "
                       f"{technique} — reusable on SSH/FTP/RDP/MySQL",
                       data={"count": len(harvested)})

        if any(w in output.lower() for w in
               ("meterpreter", "session opened", "command shell",
                "uid=", "www-data")):
            if "execution" in self.kill_chain:
                self.kill_chain["execution"].status = "success"
                self.kill_chain["execution"].detail = (
                    f"shell/session evidence via {technique}")
                self.kill_chain["execution"].completed_at = (
                    time.strftime("%H:%M:%S"))
            self._emit("success", "execution_evidence",
                       "Output shows shell/session evidence — execution phase "
                       "marked complete",
                       data={"technique": technique})

        # Mark the following phase as the active one.
        idx = (self.KILL_CHAIN_PHASES.index(phase)
               if phase in self.KILL_CHAIN_PHASES else 0)
        if idx + 1 < len(self.KILL_CHAIN_PHASES):
            next_phase = self.KILL_CHAIN_PHASES[idx + 1]
            if self.kill_chain[next_phase].status in ("pending", "running"):
                self.kill_chain[next_phase].status = "running"
                self.kill_chain[next_phase].started_at = time.strftime("%H:%M:%S")

        self._emit("success", "phase_completed",
                   f"{technique} SUCCESS on {target_host} — {phase} complete")

    def _on_failure(self, target: Dict[str, Any], result: Dict[str, Any]):
        """Handle failed attack — try alternative."""
        technique = target.get("technique", "")
        target_host = target.get("target", "")
        self._remember(target, "failure",
                       detail=f"{technique} FAILED on {target_host}")

        self._emit("failure", "attack_failed",
                   f"{technique} FAILED on {target_host} — will try alternative",
                   success=False)

        # Mark kill chain phase for retry
        if "initial_access" in self.kill_chain:
            if self.kill_chain["initial_access"].status != "success":
                self.kill_chain["initial_access"].status = "pending"

    # ── Campaign mode ────────────────────────────────────────────────
    def campaign_legs(self) -> List[str]:
        """The estate, one leg per authorized root, in scope order.

        Scope order matters: the declared domain is worked first, then
        extra_scope in the order the operator wrote it. Sorting
        alphabetically would silently start the campaign on an unrelated
        sibling root.
        """
        seen: List[str] = []
        for root in self.scope_roots():
            r = (root or "").strip().lower().rstrip(".")
            if r and r not in seen:
                seen.append(r)
        return seen

    def campaign_state(self) -> Dict[str, Any]:
        """Per-leg progress, for the console and for the operator."""
        return {
            "campaign": self.campaign,
            "current_leg": (self._campaign_legs[self._campaign_leg_idx]
                            if 0 <= self._campaign_leg_idx
                            < len(self._campaign_legs) else ""),
            "leg_index": self._campaign_leg_idx,
            "legs": list(self._campaign_legs),
            "leg_state": dict(self._campaign_state),
        }

    def _campaign_begin(self) -> bool:
        """Seed the leg list. False when there is nothing to campaign over."""
        # Backfill the declared domain from the scan FIRST: the loop calls
        # this before the first _recon, so when the caller launched by
        # scan_id alone target_domain is still empty and the campaign would
        # see extra_scope only — silently dropping the engagement's own root.
        if not self.target_domain and self.scan_id:
            try:
                import db_store
                data = db_store.get_scan(self.scan_id, self.db_path) or {}
                dom = str(data.get("domain") or "").strip().lower()
                if dom:
                    self.target_domain = dom
            except Exception:
                pass
        legs = self.campaign_legs()
        if not legs:
            return False
        self._campaign_legs = legs
        self._campaign_leg_idx = 0
        self._campaign_state = {
            leg: {"findings": 0, "creds": 0, "foothold": False,
                  "moves": 0, "closed": False}
            for leg in legs
        }
        # Point leg 1 at its own scan too: the caller may have started the
        # campaign on a scan that belongs to a different root, and recon
        # would then read someone else's data for the whole first leg.
        self._point_at_leg(legs[0])
        self._emit("recon", "campaign_start",
                   f"Campaign over {len(legs)} leg(s): {', '.join(legs)}")
        return True

    def _campaign_leg_enriched(self) -> bool:
        """Try to give the current leg real data, at most once per leg.

        A leg often has a stored scan with no port data (scanned without
        --ports), which leaves the advisor nothing to score — that is not a
        drained target, it is a thin scan. Live recon fixes it; without the
        once-per-leg guard the loop would retry the same empty target on
        every remaining iteration and never advance.
        """
        if not self._live_hosts:
            subs = self._live_subdomain_recon()
            if subs:
                self._emit("recon", "campaign_live_recon",
                           f"leg {self.target_domain}: live recon found "
                           f"{len(subs)} host(s) with service data")
                self.scan_id = 0  # force _recon to re-read and merge
                self._live_hosts = subs
                return True
        # Nothing more this leg can give without a fresh scan.
        return False

    def _point_at_leg(self, leg: str) -> None:
        """Load the newest scan for this leg so recon has real data.

        list_scans is already newest-first (ORDER BY ts DESC, id DESC), so
        taking the first match is the recent one — reversing would pin the
        leg to the oldest scan of that domain.
        """
        self.target_domain = leg
        self.scan_id = 0
        self._live_hosts = []
        try:
            import db_store
            for s in db_store.list_scans(self.db_path):
                if s.get("domain") == leg:
                    self.scan_id = s["id"]
                    break
        except Exception:
            pass

    def _campaign_advance(self) -> bool:
        """Close this leg and move to the next.

        A campaign step is not a fresh start: credentials and a proven
        foothold carry over, because that is what lets the next leg begin
        at credential reuse instead of re-running initial access. The leg
        that produced them is recorded as the one that paid for it.
        """
        if not self.campaign:
            return False
        if not self._campaign_legs and not self._campaign_begin():
            return False
        cur = (self._campaign_legs[self._campaign_leg_idx]
               if 0 <= self._campaign_leg_idx < len(self._campaign_legs) else "")
        if cur:
            st = self._campaign_state.setdefault(cur, {})
            st["creds"] = len(self.credentials_found)
            st["foothold"] = bool(
                (self.kill_chain.get("execution") or None)
                and self.kill_chain["execution"].status == "success")
            st["moves"] = len([e for e in self.events
                               if e.action in ("brain_step", "chain_step",
                                               "target_selected")])
            st["closed"] = True
        if self._campaign_leg_idx + 1 >= len(self._campaign_legs):
            self._emit("idle", "campaign_complete",
                       f"Campaign finished — {len(self._campaign_legs)} leg(s) "
                       f"worked, {len(self.credentials_found)} credential(s) held")
            return False
        self._campaign_leg_idx += 1
        nxt = self._campaign_legs[self._campaign_leg_idx]
        # Re-point the engagement at the new leg. Anything the previous leg
        # proved stays in memory (credentials_found, kill chain), so the
        # advisor sees it and the new leg can start at credential reuse.
        self._point_at_leg(nxt)
        self._emit("recon", "campaign_leg",
                   f"leg {self._campaign_leg_idx + 1}/{len(self._campaign_legs)}: "
                   f"{cur} closed -> advancing to {nxt}")
        return True

    def _try_alternative_scan(self) -> bool:
        """No attack paths from stored data — enrich with live recon instead.

        Stored scans often carry subdomains but no port data (e.g. scans run
        without --ports), which leaves the advisor nothing to score. Rather
        than hopping to an unrelated domain's scan, probe the target's own
        subdomains and fold the results back into the live scan data.
        """
        subs = self._live_subdomain_recon()
        if subs:
            self._emit("recon", "live_recon",
                       f"Live recon: {len(subs)} host(s) with service data")
            self.scan_id = 0  # force _recon to re-read and merge
            self._live_hosts = subs
            return True

        # Last resort: an older scan for the same domain that has host data.
        try:
            import db_store
            scans = db_store.list_scans(self.db_path)
            for s in reversed(scans):
                if s["id"] == self.scan_id or s.get("domain") != self.target_domain:
                    continue
                data = db_store.get_scan(s["id"], self.db_path)
                if data.get("hosts") or data.get("findings"):
                    self.scan_id = s["id"]
                    self._emit("recon", "alternative_scan",
                               f"Switched to scan #{s['id']} ({s.get('domain', '?')})")
                    return True
        except Exception:
            pass
        return False

    def _live_subdomain_recon(self) -> List[Dict[str, Any]]:
        """Probe known subdomains of the target for open services.

        Uses the existing port scanner when available so the advisor gets
        real service flags (ssh/ftp/http/smb) to score techniques against.
        """
        try:
            import socket
            from urllib.parse import urlparse

            data = {}
            if self.scan_id:
                import db_store
                data = db_store.get_scan(self.scan_id, self.db_path)
            subs = data.get("subdomains") or []
            if isinstance(subs, str):
                import json as _json
                try:
                    subs = _json.loads(subs)
                except (ValueError, TypeError):
                    subs = []
            names = []
            for s in subs:
                name = s if isinstance(s, str) else (s or {}).get("host", "")
                if name:
                    names.append(name)
            if self.target_domain and self.target_domain not in names:
                names.append(self.target_domain)
            if not names:
                return []

            probe_ports = [21, 22, 80, 443, 445, 3306, 3389, 8080]
            out: List[Dict[str, Any]] = []
            for name in names[:12]:
                ports = []
                for p in probe_ports:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1.5)
                    try:
                        if s.connect_ex((name, p)) == 0:
                            ports.append({"port": p, "service": _guess_service(p)})
                    except OSError:
                        pass
                    finally:
                        s.close()
                if ports:
                    out.append({"host": name, "ip": "", "ports": ports,
                                "findings": []})
            return out
        except Exception as e:
            self._emit("recon", "live_recon_error", str(e), success=False)
            return []

    def _run_in_kali(self, command: str, timeout: int = 60) -> Dict[str, Any]:
        """Run a command inside the kali-as container."""
        try:
            r = subprocess.run(
                ["docker", "exec", "-i", KALI_CONTAINER,
                 "bash", "-c", command],
                capture_output=True, text=True, timeout=timeout,
            )
            return {
                "exit_code": r.returncode,
                "stdout": r.stdout or "",
                "stderr": r.stderr or "",
            }
        except subprocess.TimeoutExpired:
            return {"exit_code": -1, "stdout": "", "stderr": "timeout"}
        except Exception as e:
            return {"exit_code": -1, "stdout": "", "stderr": str(e)}

    def get_kill_chain_report(self) -> Dict[str, Any]:
        """Generate a kill chain completion report."""
        completed = sum(1 for kp in self.kill_chain.values()
                        if kp.status == "success")
        total = len(self.KILL_CHAIN_PHASES)
        return {
            "agent_id": self.agent_id,
            "target": self.target_domain,
            "scan_id": self.scan_id,
            "total_iterations": self.iteration,
            "phases_completed": completed,
            "phases_total": total,
            "completion_pct": round(completed / total * 100, 1),
            "credentials_found": len(self.credentials_found),
            "phases": {
                phase: {
                    "status": kp.status,
                    "detail": kp.detail,
                    "completed_at": kp.completed_at,
                }
                for phase, kp in self.kill_chain.items()
            },
        }


# Backward-compatible alias: older imports (and the dashboard) still say
# AutonomousAgent. Keep it working; new code should use Knull.
AutonomousAgent = Knull
