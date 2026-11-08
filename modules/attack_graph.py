"""attack_graph.py — interactive attack path graph builder.

Builds a rich graph from scan data: subdomains → IPs → ports →
services → vulnerabilities → admin panels → attack paths.

Output is a JSON payload for the dashboard's Cytoscape.js renderer:
    {nodes: [{id, label, type, risk, meta...}], edges: [{source, target, label, risk}]}

Node types: Internet, CDN, Origin, Subdomain, Service, Vulnerability,
            AdminPanel, Email, CloudAsset
Edge types: resolves_to, exposes, serves, vulnerable_to, hosts,
            connects_to, attack_path
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AttackSurface.AttackGraph")


def _jload(v):
    if isinstance(v, str):
        try:
            return json.loads(v)
        except Exception:
            return v
    return v


def build_graph(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """Build the interactive graph payload from a stored scan dict.

    Accepts db_store.get_scan() output (sections + hosts + findings).
    """
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    seen_nodes: set = set()
    seen_edges: set = set()

    def add_node(nid: str, ntype: str, label: str = "", risk: int = 0,
                 **meta):
        if nid in seen_nodes:
            # merge risk (keep max)
            for n in nodes:
                if n["id"] == nid:
                    n["risk"] = max(n.get("risk", 0), risk)
                    for k, v in meta.items():
                        if v and not n.get(k):
                            n[k] = v
                    return
            return
        seen_nodes.add(nid)
        node = {"id": nid, "type": ntype, "label": label or nid,
                "risk": risk}
        node.update({k: v for k, v in meta.items() if v})
        nodes.append(node)

    def add_edge(src: str, dst: str, etype: str, label: str = "",
                 risk: int = 0):
        key = (src, dst, etype)
        if key in seen_edges:
            return
        seen_edges.add(key)
        edges.append({"source": src, "target": dst, "type": etype,
                      "label": label or etype, "risk": risk})

    domain = scan_data.get("domain") or ""
    hosts = scan_data.get("hosts") or []
    subdomains = scan_data.get("subdomains") or []
    findings = scan_data.get("findings") or []
    sections = scan_data.get("sections") or {}

    # --- Internet node ---
    add_node("internet", "Internet", "Internet", 0)

    # --- Domain / subdomains ---
    if domain:
        add_node(domain, "Subdomain", domain, 50, is_root=True)
        add_edge("internet", domain, "resolves_to", "", 10)

    for sub in subdomains:
        if sub == domain:
            continue
        add_node(sub, "Subdomain", sub, 30)
        add_edge(domain, sub, "hosts", "", 5)

    # --- Hosts (IPs) + ports + services ---
    for h in hosts:
        host = h.get("host") or ""
        ip = h.get("ip") or ""
        ports = _jload(h.get("ports")) or []
        tech = _jload(h.get("tech")) or []

        if ip:
            ip_id = f"ip:{ip}"
            add_node(ip_id, "Origin", ip, 40)
            add_edge(host or domain, ip_id, "resolves_to", "", 15)

        for p in ports:
            if not isinstance(p, dict):
                continue
            port_num = p.get("port", 0)
            svc = p.get("service") or p.get("service_versioned") or "unknown"
            svc_id = f"svc:{host}:{port_num}"
            # risk: high for known-dangerous ports
            danger = {21: 70, 22: 50, 23: 80, 25: 40, 53: 30,
                      110: 40, 139: 60, 143: 40, 3306: 70, 3389: 80,
                      5432: 70, 5900: 60, 6379: 80, 8080: 40, 27017: 80}
            svc_risk = danger.get(port_num, 25)
            add_node(svc_id, "Service", f"{svc} :{port_num}", svc_risk,
                     port=port_num, service=svc)
            target = ip_id if ip else (host or domain)
            add_edge(target, svc_id, "exposes", f"port {port_num}",
                     svc_risk)

        for t in tech:
            if isinstance(t, str) and t:
                tech_id = f"tech:{t}"
                add_node(tech_id, "Technology", t, 10)
                add_edge(host or domain, tech_id, "runs", "", 5)

    # --- Findings → vulnerabilities ---
    for row in findings:
        if isinstance(row, dict):
            title = row.get("title") or ""
            host = row.get("host") or domain
        else:
            title = str(row)
            host = domain
        if not title:
            continue
        # classify severity from text
        tl = title.lower()
        sev = 30
        if "critical" in tl or "exploit" in tl:
            sev = 90
        elif "high" in tl or "exposed" in tl or "public exposure" in tl:
            sev = 70
        elif "medium" in tl or "missing" in tl:
            sev = 50
        elif "low" in tl or "info" in tl:
            sev = 20
        # short label
        label = re.sub(r"\*+", "", title)[:60]
        vid = f"vuln:{host}:{abs(hash(title)) % 10**8}"
        add_node(vid, "Vulnerability", label, sev, title=title[:200])
        add_edge(host or domain, vid, "vulnerable_to", "", sev)

    # --- Structured nuclei findings: severity-graded vulnerabilities ---
    try:
        from modules.attack_advisor import _host_of_url
    except Exception:
        _host_of_url = lambda u: ""  # noqa: E731
    nuc_rows = sections.get("nuclei") or []
    for n in (nuc_rows if isinstance(nuc_rows, list) else [])[:150]:
        if not isinstance(n, dict):
            continue
        url = str(n.get("url") or n.get("matched_at") or "")
        nhost = _host_of_url(url) or domain
        sev = str(n.get("severity") or "info").lower()
        risk = {"critical": 95, "high": 80, "medium": 55,
                "low": 30}.get(sev, 15)
        label = str(n.get("name") or n.get("template_id") or "finding")[:70]
        nid = f"nuc:{n.get('template_id','')}:{url}"[:200]
        add_node(nid, "Vulnerability", label, risk,
                 title=f"{sev.upper()}: {label}",
                 cve=str(n.get("cve") or ""), url=url, severity=sev)
        add_edge(nhost, nid, "vulnerable_to", sev, risk)

    # --- CVE watchlist (--cves / --cves-deep): the real vulnerabilities ---
    cve_map = sections.get("cves") or {}
    if isinstance(cve_map, dict):
        for host, rows in cve_map.items():
            if not host or not isinstance(rows, list):
                continue
            if host not in seen_nodes:
                add_node(host, "Subdomain", host, 30)
            for row in rows:
                if not isinstance(row, dict):
                    continue
                match = str(row.get("match") or "")
                exact = match == "cpe_exact"
                for c in (row.get("cves") or [])[:8]:
                    if not isinstance(c, dict):
                        continue
                    cid = str(c.get("cve") or c.get("id") or "")
                    if not cid:
                        continue
                    try:
                        cvss = float(c.get("cvss") or 0)
                    except (TypeError, ValueError):
                        cvss = 0.0
                    ctx_risk = c.get("contextual_risk")
                    if isinstance(ctx_risk, (int, float)) and ctx_risk:
                        risk = int(ctx_risk)
                    elif cvss:
                        risk = min(100, int(cvss * 10))
                    else:
                        risk = 50 if exact else 35
                    kev = bool(c.get("kev"))
                    if kev:
                        risk = max(risk, 90)
                    label = f"{cid}{' ⚑KEV' if kev else ''}"
                    add_node(f"cve:{cid}:{host}", "CVE", label, risk,
                             title=cid, cve=cid, cvss=cvss, kev=kev,
                             epss=c.get("epss"), match=match,
                             tech=row.get("tech") or "",
                             summary=str(c.get("summary") or "")[:200])
                    add_edge(host, f"cve:{cid}:{host}", "vulnerable_to",
                             "exact" if exact else "keyword", risk)

    # --- Admin panels ---
    admin = sections.get("admin_panels") or {}
    for host, panels in admin.items():
        for p in (panels or [])[:5]:
            if not isinstance(p, dict):
                continue
            url = p.get("url") or p.get("found_on") or ""
            name = p.get("name") or p.get("panel") or "Admin"
            pid = f"admin:{host}:{url or name}"
            add_node(pid, "AdminPanel", f"{name}", 75, url=url)
            add_edge(host, pid, "hosts", "admin panel", 70)

    # --- Email / spoofing ---
    es = sections.get("email_security") or {}
    if es.get("email_spoofing_possible"):
        eid = f"email:{domain}"
        add_node(eid, "Email", "Email Spoofing", 80)
        add_edge("internet", eid, "attack_path", "spoofing", 80)

    # --- CDN detection (mark CDN-fronted hosts) ---
    for h in hosts:
        host = h.get("host") or ""
        cdn = h.get("cdn") or ""
        if cdn:
            cid = f"cdn:{cdn}"
            add_node(cid, "CDN", f"CDN: {cdn}", 5)
            add_edge(cid, host or domain, "proxies", "", 5)

    # --- MSF suggestions ---
    msf = sections.get("msf_suggestions") or []
    for s in msf[:30]:
        if not isinstance(s, dict):
            continue
        host = s.get("host") or ""
        mod = s.get("module") or ""
        stage = s.get("stage") or "check"
        mid = f"msf:{host}:{mod}"
        mlabel = mod.split("/")[-1] if "/" in mod else mod
        mris = 85 if stage == "exploit" else 40
        add_node(mid, "Vulnerability", f"MSF: {mlabel}", mris,
                 module=mod, stage=stage)
        add_edge(host, mid, "attack_path",
                 "EXPLOIT" if stage == "exploit" else "CHECK", mris)

    graph = {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "nodes": len(nodes),
            "edges": len(edges),
            "by_type": {},
        },
    }
    for n in nodes:
        t = n["type"]
        graph["stats"]["by_type"][t] = graph["stats"]["by_type"].get(t, 0) + 1
    return graph


def save_graph(graph: Dict[str, Any], path: str = "reports/graph_data.json") -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(graph, f, ensure_ascii=False, indent=1)
    return path


# ---------------------------------------------------------------------------
# Chained (multi-hop) attack paths
# ---------------------------------------------------------------------------

# Which kill-chain stage each advisor technique belongs to.
_ACCESS = {"ftp_anonymous", "default_creds", "sqli", "cve_exploit",
           "subdomain_takeover", "xss"}
_CREDENTIAL = {"ssh_brute", "ftp_brute", "rdp_brute", "mysql_brute",
              "smb_null_session", "ssh_key_auth"}

# Kill-chain stage names in canonical order — the phase keys the kill
# chain itself uses (Knull.KILL_CHAIN_PHASES), mapped to advisor keys.
_KC_STAGE_OF = {
    # initial access
    "initial_access": ("default_creds", "sqli", "cve_exploit",
                       "subdomain_takeover", "xss"),
    # credential access
    "credential_access": ("ssh_brute", "ftp_brute", "rdp_brute", "mysql_brute",
                          "smb_null_session", "ssh_key_auth", "ssh_key_auth"),
}

# Advisor technique -> (kill-chain phase it opens into, gate proof).
# A deep step is admitted only when the proof its phase requires is
# present in the scan data's engagement state.
_DEEP_ADMIT = {
    # foothold proven -> privilege escalation / persistence may be planned
    "sudo_check": "privilege_escalation",
    "ssh_persist": "persistence",
    # creds proven -> lateral movement may be planned
    "cred_reuse": "lateral_movement",
    # msf module present on an exposed service -> access-level move
    "msf_exploit": "initial_access",
}

# Port each credential technique needs open on its target.
_CRED_PORT = {"ssh_brute": 22, "ssh_key_auth": 22, "ftp_brute": 21,
              "rdp_brute": 3389, "mysql_brute": 3306, "smb_null_session": 445}

# Service an access technique lands on — used to reject redundant chains
# (anonymous FTP login followed by FTP brute force is the same service,
# not a pivot).
_ACCESS_PORT = {"ftp_anonymous": 21}

# How well an access technique actually enables a credential attack:
#   strong    — yields credentials, code exec, or domain foothold
#   plausible — may expose credential material (e.g. files on anon FTP)
#   (xss is deliberately absent: a browser-side bug gives no server
#   foothold, so "XSS → SSH brute force" is not a chain.)
_ACCESS_ENABLES_CREDENTIAL = {"default_creds", "sqli", "cve_exploit",
                              "subdomain_takeover"}
_ACCESS_MAY_LEAD = {"ftp_anonymous"}


def _root_domain(host: str) -> str:
    """Registrable-ish tail (last two labels) for 'same estate' checks."""
    parts = [p for p in (host or "").lower().split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "")


def _open_ports(scan_data: Dict[str, Any]) -> Dict[str, set]:
    """{host: {port, ...}} from the stored scan.

    Falls back to ports written as finding text for scans whose
    hosts[].ports column is empty (nmap phase skipped or crashed).
    """
    out: Dict[str, set] = {}
    for h in (scan_data.get("hosts") or []):
        host = h.get("host") or ""
        ports = _jload(h.get("ports")) or []
        s = set()
        for p in ports:
            if isinstance(p, dict):
                raw = p.get("port")
                if raw is None:
                    continue
                try:
                    s.add(int(raw))
                except (TypeError, ValueError):
                    continue
            elif isinstance(p, int):
                s.add(p)
        if host and s:
            out[host] = s

    # Recover ports recorded only as "**Public Exposure**: X is open on
    # port N" findings.
    try:
        from modules.attack_advisor import ports_from_findings
    except Exception:
        return out
    for f in (scan_data.get("findings") or []):
        if isinstance(f, dict) and f.get("host"):
            for p in ports_from_findings([f]):
                out.setdefault(f["host"], set()).add(p)
    return out


def find_chains(scan_data: Dict[str, Any],
                max_chains: int = 6) -> List[Dict[str, Any]]:
    """Build ordered multi-hop attack chains from the advisor's paths.

    A chain is only produced when the steps actually link up:
      * step 1 must grant initial access,
      * step 2 must need credentials, and
      * both must sit on the same host (with that service confirmed open)
        or on two hosts of the same root domain.

    When the scan data carries engagement proof (_engagement from
    Knull._recon — foothold_verified / creds_held), deeper chains are
    appended: each deep step is gated on the proof its technique
    requires, so a persistence step never enters a plan without a
    verified foothold.

    Chained probability is the product of the step probabilities — a
    chain is only as likely as its weakest link, so a 2-step chain with
    41% and 30% steps scores ~12%, not 71%.
    """
    try:
        from modules.attack_advisor import recommend_attacks
        order = (recommend_attacks(scan_data).get("execution_order") or [])
    except Exception as e:
        logger.warning("find_chains: advisor failed: %s", e)
        return []
    if not order:
        return []

    ports_by_host = _open_ports(scan_data)

    access = [p for p in order if _tech_key(p) in _ACCESS]
    credential = [p for p in order if _tech_key(p) in _CREDENTIAL]

    engagement = scan_data.get("_engagement") or {}
    if not isinstance(engagement, dict):
        engagement = {}

    foothold_ok = bool(engagement.get("foothold"))
    creds_ok = int(engagement.get("creds") or 0) > 0

    chains: List[Dict[str, Any]] = []
    for a in access:
        for c in credential:
            reason = _link_reason(a, c, ports_by_host)
            if not reason:
                continue
            steps = [a, c]
            prob = 1.0
            for s in steps:
                prob *= float(s.get("probability") or 0.1)
            score = sum(float(s.get("score") or 0) for s in steps) * 0.75
            akey = _tech_key(a)
            ckey = _tech_key(c)
            chains.append({
                "id": f"chain:{akey}->{ckey}:{c.get('target', '')}",
                "steps": [_step_view(s, i + 1) for i, s in enumerate(steps)],
                "score": round(score, 1),
                "probability": round(prob, 4),
                "confidence": ("strong" if akey in _ACCESS_ENABLES_CREDENTIAL
                               else "plausible"),
                "reason": reason,
                "hops": len(steps),
            })

    # Deeper chains (3-5 hops) gated on engagement proof. Each deep step
    # gets a phase label from the kill chain and is only admitted when the
    # proof that phase consumes is on record:
    #   foothold_verified -> privilege_escalation / persistence steps
    #   creds_held        -> lateral_movement steps
    deep: List[Dict[str, Any]] = []
    for a in access:
        for mid, mid_phase in _DEEP_ADMIT.items():
            mstep = next((p for p in order
                          if _tech_key(p) == mid), None)
            if not mstep:
                continue
            phase_ok = True
            if _DEEP_ADMIT[mid] == "privilege_escalation":
                phase_ok = foothold_ok
            elif _DEEP_ADMIT[mid] == "persistence":
                phase_ok = foothold_ok
            elif _DEEP_ADMIT[mid] == "lateral_movement":
                phase_ok = creds_ok
            elif _DEEP_ADMIT[mid] == "initial_access":
                phase_ok = bool(engagement.get("msf_module_present"))
            if not phase_ok:
                continue
            for c in credential:
                if _tech_key(c) != "cred_reuse" and mid_phase != "initial_access":
                    continue
                reason = _link_reason(a, c, ports_by_host)
                if not reason:
                    continue
                steps = [a, mstep, c]
                prob = 1.0
                for s in steps:
                    prob *= float(s.get("probability") or 0.1)
                score = sum(float(s.get("score") or 0) for s in steps) * 0.6
                akey = _tech_key(a)
                mkey = _tech_key(mstep)
                ckey = _tech_key(c)
                deep.append({
                    "id": f"chain:{akey}->{mkey}->{ckey}:{c.get('target', '')}",
                    "steps": [_step_view(s, i + 1) for i, s in enumerate(steps)],
                    "score": round(score, 1),
                    "probability": round(prob, 4),
                    "confidence": "strong" if akey in _ACCESS_ENABLES_CREDENTIAL
                                   else "plausible",
                    "reason": (f"{a.get('technique')} -> {mstep.get('technique')} "
                                f"-> {c.get('technique')}"),
                    "hops": len(steps),
                })

    chains = chains + deep

    # Single-step fallback so a scan with no linkable pair still has a plan.
    if not chains:
        for a in (access or order)[:max_chains]:
            chains.append({
                "id": f"chain:1hop:{_tech_key(a)}:{a.get('target', '')}",
                "steps": [_step_view(a, 1)],
                "score": float(a.get("score") or 0),
                "probability": float(a.get("probability") or 0),
                "reason": "single-step path — no linkable follow-up found",
                "hops": 1,
                "confidence": "single",
            })

    # Strong chains first, then by chained probability.
    chains.sort(key=lambda ch: (
        0 if ch.get("confidence") == "strong" else 1,
        -ch["probability"],
    ))
    return chains[:max_chains]


# Built lazily from ATTACK_TECHNIQUES to avoid a hard import at module load.
_TECH_NAME_TO_KEY: Dict[str, str] = {}


def _tech_key(path: Dict[str, Any]) -> str:
    """Map a display name like 'SSH Brute Force' back to its technique key."""
    if not _TECH_NAME_TO_KEY:
        try:
            from modules.attack_advisor import ATTACK_TECHNIQUES
            for k, meta in ATTACK_TECHNIQUES.items():
                _TECH_NAME_TO_KEY[(meta.get("name") or k).strip().lower()] = k
        except Exception:
            return ""
    return _TECH_NAME_TO_KEY.get((path.get("technique") or "").strip().lower(), "")


def _link_reason(a: Dict[str, Any], c: Dict[str, Any],
                 ports_by_host: Dict[str, set]) -> str:
    """Return a human-readable justification, or '' when steps don't link."""
    at, ct = (a.get("target") or ""), (c.get("target") or "")
    if not at or not ct:
        return ""
    key = _tech_key(c)
    need = _CRED_PORT.get(key)
    open_here = ports_by_host.get(ct, set())
    akey = _tech_key(a)

    # Reject a chain whose first step already lands on the service the
    # second step attacks: anonymous FTP login followed by FTP brute force
    # is one service, not a pivot.
    if need and need == _ACCESS_PORT.get(akey):
        return ""

    # Reject access steps that grant no server-side foothold (XSS) — the
    # second step could not use what the first one wins.
    if akey not in _ACCESS_ENABLES_CREDENTIAL and akey not in _ACCESS_MAY_LEAD:
        return ""

    if at == ct:
        if need and open_here and need not in open_here:
            return ""  # the service the second step needs isn't open
        port_note = f"port {need} confirmed open" if need and need in open_here \
            else "same host"
        return (f"{a.get('technique')} gets a foothold on {at}; "
                f"{c.get('technique')} then reuses it ({port_note})")

    if _root_domain(at) == _root_domain(ct):
        if need and open_here and need not in open_here:
            return ""
        return (f"{a.get('technique')} on {at} opens the estate; "
                f"{c.get('technique')} continues on sibling host {ct}")
    return ""


def _step_view(path: Dict[str, Any], n: int) -> Dict[str, Any]:
    return {
        "n": n,
        "technique": path.get("technique", ""),
        "technique_key": _tech_key(path),
        "target": path.get("target", ""),
        "score": path.get("score"),
        "probability": path.get("probability"),
        "command": path.get("command", ""),
    }
