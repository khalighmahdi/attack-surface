"""
core/runner.py
================
Unified orchestrator for the attack-surface pipeline.

Pipeline (each phase is isolated and can be skipped via flags):

    1. Discovery
       - subdomains.enumerate_subdomains(domain)
       - mx_record_discovery.discover_mx_records(domain)         [optional]
       - historical_dns_discovery.discover_historical_origins()  [optional]

    2. Probing
       - alive.check_alive(subdomains)
       - ports.scan_ports(alive_hosts)                           [optional, needs nmap]
       - header_audit.audit_headers(alive_hosts)
       - tech_fingerprint.fingerprint_technologies(alive_hosts)

    3. Admin / Origin
       - admin_finder.find_admin_panels(alive_hosts)             [optional]
       - origin_ip_discovery.subdomain_ip_correlation(alive_hosts)

    4. Analysis
       - risk_scoring.calculate_risk(events)
       - attack_path_engine.build_attack_paths(ctx)
       - mitre_mapping.map_attack_paths_to_mitre(paths)
       - kill_chain.build_kill_chain(ctx)

    5. Visualization
       - graph_builder.build_attack_surface_graph(ctx)

    6. Export
       - report.generate_html_report(ctx.to_report_dict())
       - exporter.export_csv / export_markdown

Every phase writes its results into the ScanContext, so the report is
consistent regardless of which phases ran.
"""

from __future__ import annotations

import logging
from collections import Counter
import os
import traceback
from pathlib import Path
from typing import Optional

from core.context import ScanContext
from core.stream import ndjson_emit, init_ndjson, close_ndjson
from core.utils import sanitize_domain

from modules.mitre import TACTICS

logger = logging.getLogger("AttackSurface.Runner")


def _web_hosts(alive_hosts: list) -> list:
    """Hosts that answered HTTP (drop DNS-only entries for HTTP phases).

    Ports/header/tech phases get all alive hosts; HTTP-only modules must
    skip hosts that merely resolved in DNS, otherwise they burn timeouts
    on servers that never answer HTTP.
    """
    return [h for h in (alive_hosts or [])
            if not (isinstance(h, dict) and h.get("http_ok") is False)]


def _log_cve_total(ctx: ScanContext, label: str) -> None:
    """Report CVE counts honestly: how many are exact vs keyword.

    The old line said 'exact CVE(s)' for whatever the pass produced, which
    was wrong whenever cve_deep fell back to a keyword search.
    """
    rows = [r for v in (getattr(ctx, "cve_watchlist", None) or {}).values()
            for r in v]
    total = sum(len(r.get("cves") or []) for r in rows)
    exact = sum(1 for r in rows if r.get("match") == "cpe_exact")
    logger.info("  -> %s: %d CVE(s) across %d row(s) "
                "(%d exact CPE, %d keyword)",
                label, total, len(rows), exact, len(rows) - exact)


def _cve_id(c: Any) -> str:
    """CVE id regardless of which pass wrote it (deep uses 'id', keyword 'cve')."""
    if not isinstance(c, dict):
        return ""
    return str(c.get("cve") or c.get("id") or "")


def _merge_cve_watchlist(ctx: ScanContext, new: dict) -> None:
    """Merge CVE results into ctx instead of overwriting them.

    --cves-deep runs before --cves; both assigned ctx.cve_watchlist, so
    the keyword pass silently erased every exact CPE hit. When both passes
    cover the same technology their CVE lists are unioned (by id) and the
    richer metadata wins — keyword hits carry EPSS/KEV/contextual risk
    that the deep pass does not compute, and vice versa.
    """
    cur = getattr(ctx, "cve_watchlist", None) or {}
    for host, rows in (new or {}).items():
        existing = cur.setdefault(host, [])
        by_tech = {(r.get("tech") or "").lower(): r for r in existing}
        for r in rows:
            tech = (r.get("tech") or "").lower()
            mine = by_tech.get(tech)
            if mine is None:
                existing.append(r)
                by_tech[tech] = r
                continue
            seen = {_cve_id(c) for c in (mine.get("cves") or [])}
            for c in (r.get("cves") or []):
                cid = _cve_id(c)
                if cid and cid not in seen:
                    mine.setdefault("cves", []).append(c)
                    seen.add(cid)
            if r.get("match") == "cpe_exact":
                mine["match"] = "cpe_exact"
            if r.get("cpe") and not mine.get("cpe"):
                mine["cpe"] = r["cpe"]
            for field in ("cvss", "epss", "kev", "contextual_risk"):
                if mine.get(field) in (None, "") and r.get(field) not in (None, ""):
                    mine[field] = r[field]
    ctx.cve_watchlist = cur


class ScannerRunner:
    def __init__(
        self,
        skip_ports: bool = False,
        skip_admin: bool = False,
        skip_mx: bool = False,
        skip_historical: bool = False,
        skip_origin: bool = False,
        max_subdomains: int = 50,
        rate_limiter=None,
        scope=None,
        checkpoint_path: str | None = None,
        resume_from: str | None = None,
        use_baseline: bool = True,
        syslog_target: str | None = None,
        webhook_url: str | None = None,
        telegram_token: str | None = None,
        telegram_chat: str | None = None,
        map_cves: bool = False,
        cve_deep: bool = False,
        active_poc: bool = False,
        critical_web: bool = True,
        # NEW: Advanced modules (v0.19)
        enable_asm: bool = False,
        enable_cloud: bool = False,
        enable_api_scan: bool = False,
        auth_config: str | None = None,
        sbom_file: str | None = None,
        enable_mitre: bool = False,
        report_type: str | None = None,
        integrations_config: str | None = None,
        enable_redteam: bool = False,
        # NEW: Metasploit service mapping (v0.22) — automatic by default:
        # exposed services get check modules, confirmed-vuln versions get
        # an exploit+payload one-liner for the operator terminal.
        enable_msf_map: bool = True,
        # NEW: httpx + nuclei integration (v0.23)
        enable_httpx: bool = False,
        enable_nuclei: bool = False,
        nuclei_severity: str = "medium,high,critical",
    ):
        self.cve_deep = cve_deep
        self.active_poc = active_poc
        self.critical_web = critical_web
        self.use_baseline = use_baseline
        self.syslog_target = syslog_target
        self.webhook_url = webhook_url
        self.telegram_token = telegram_token
        self.telegram_chat = telegram_chat
        self.map_cves = map_cves
        self.blue_team_report: dict | None = None
        self.skip_ports = skip_ports
        self.skip_admin = skip_admin
        self.skip_mx = skip_mx
        self.skip_historical = skip_historical
        self.skip_origin = skip_origin
        self.max_subdomains = max_subdomains
        # NEW: Advanced modules flags
        self.enable_asm = enable_asm
        self.enable_cloud = enable_cloud
        self.enable_api_scan = enable_api_scan
        self.auth_config = auth_config
        self.sbom_file = sbom_file
        self.enable_mitre = enable_mitre
        self.report_type = report_type
        self.integrations_config = integrations_config
        # Red Team (v0.20)
        self.enable_redteam = enable_redteam
        # Metasploit service mapping (v0.22)
        self.enable_msf_map = enable_msf_map
        # httpx + nuclei (v0.23)
        self.enable_httpx = enable_httpx
        self.enable_nuclei = enable_nuclei
        self.nuclei_severity = nuclei_severity
        # New: rate limiting, scope validation, checkpointing
        from core.rate_limiter import get_limiter
        self.limiter = rate_limiter or get_limiter()
        from core.scope import ScopeFilter
        self.scope = scope or ScopeFilter(primary="__unset__")
        self.checkpoint_path = checkpoint_path
        self.resume_from = resume_from

    # ------------------------------------------------------------------
    # Phase helpers
    # ------------------------------------------------------------------
    def _safe(self, phase, fn, *args, **kwargs):
        """Run a phase function, never abort the scan on failure."""
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            tb = traceback.format_exc(limit=2)
            logger.error("Phase %s failed: %s", phase, e)
            logger.debug(tb)
            # Stash the error on the context if a ctx was passed
            if args and isinstance(args[0], ScanContext):
                args[0].add_error(phase, str(e))
            return None

    def _phase_discovery(self, ctx: ScanContext) -> None:
        logger.info("[Phase 1] Discovery: subdomains")
        from modules.subdomains import enumerate_subdomains
        subs = self._safe("enumerate_subdomains", enumerate_subdomains, ctx.domain) or []
        # Scope enforcement: drop out-of-scope hosts before any probing
        if self.scope is not None:
            scoped = []
            for s in set(subs):
                decision = self.scope.check(s)
                if decision.allowed:
                    scoped.append(s)
                else:
                    logger.warning("  out-of-scope host dropped: %s", s)
            subs = scoped
        # Cap to avoid runaway scans
        ctx.subdomains = sorted(set(subs))[: self.max_subdomains]
        logger.info("  -> %d subdomains", len(ctx.subdomains))

        if not self.skip_mx:
            logger.info("[Phase 1] Discovery: MX records")
            try:
                from modules.mx_record_discovery import discover_mx_records
                mx = self._safe("discover_mx_records", discover_mx_records, ctx.domain) or {}
                ctx.mx_records = mx.get("mx_records", []) if isinstance(mx, dict) else []
                if mx.get("error"):
                    ctx.add_error("mx_record_discovery", mx["error"])
            except ImportError:
                logger.warning("  mx_record_discovery not available (missing dnspython?)")

        if not self.skip_historical:
            logger.info("[Phase 1] Discovery: historical DNS (crt.sh)")
            try:
                from modules.historical_dns_discovery import discover_historical_origins
                hist = self._safe("discover_historical_origins",
                                  discover_historical_origins, ctx.domain) or []
                if isinstance(hist, list):
                    # keep only in-scope historical entries
                    kept = []
                    for item in hist:
                        sub = item.get("subdomain")
                        if sub and self.scope is not None and not self.scope.check(sub).allowed:
                            logger.warning("  out-of-scope historical host dropped: %s", sub)
                            continue
                        kept.append(item)
                        if sub and sub not in ctx.subdomains:
                            ctx.subdomains.append(sub)
                    ctx.historical_dns = kept
            except ImportError:
                logger.warning("  historical_dns_discovery not available")

    def _phase_httpx_first(self, ctx: ScanContext) -> None:
        """Run httpx BEFORE header/tech so it can act as liveness authority.

        check_alive's verdict is conservative: when a WAF throttles curl
        and requests, a host is recorded as dns_resolved_no_http with
        http_ok=False, and _web_hosts() then excludes it from every HTTP
        phase. One real scan logged 'headers for 0 hosts' and
        'technologies for 0 hosts' while httpx found 9 live — which in
        turn starved CVE mapping (needs technologies), WP recon and admin
        panels. httpx is the reliable prober here, so its answer wins.
        """
        if not (self.enable_httpx or self.enable_nuclei):
            return
        try:
            from urllib.parse import urlparse

            from modules.httpx_nuclei import probe_http
            targets = list(dict.fromkeys(
                [ctx.domain] + list(ctx.subdomains or [])))
            logger.info("[Phase 2.0] httpx live inventory (liveness authority)")
            results = self._safe("probe_http", probe_http, targets,
                                 timeout=180, rate_limit=10) or []
            ctx.http_results = results
            if not results:
                # Targets routinely throttle probes (observed: 200, 000, 200
                # on consecutive tries). One slower retry before giving up.
                logger.warning("  -> httpx: 0 live on first pass — retrying "
                               "with a lower rate")
                results = self._safe("probe_http", probe_http, targets,
                                     timeout=180, rate_limit=2) or []
                ctx.http_results = results
            if not results:
                logger.warning("  -> httpx: 0 live (keeping check_alive verdict)")
                return

            by_name = {h.get("domain"): h for h in ctx.alive_hosts
                       if isinstance(h, dict)}
            known = set(by_name)
            promoted = 0
            for r in results:
                url = r.get("url") or ""
                try:
                    name = (urlparse(url).hostname or "").lower()
                except Exception:
                    name = ""
                if not name:
                    continue
                techs = r.get("tech") or []
                if isinstance(techs, list) and techs:
                    ctx.technologies[name] = list(
                        dict.fromkeys(techs))[:10]
                host = by_name.get(name)
                if host:
                    host["http_ok"] = True
                    host["http_status"] = r.get("status")
                    host["title"] = r.get("title")
                elif name not in known:
                    # httpx sees a host check_alive rejected — trust it
                    ctx.alive_hosts.append({
                        "domain": name, "ip": r.get("ip") or "",
                        "protocol": url.split(":", 1)[0],
                        "status": "alive", "http_ok": True,
                        "http_status": r.get("status"),
                        "title": r.get("title"),
                    })
                    known.add(name)
                    promoted += 1
            logger.info(
                "  -> httpx: %d live | %d host(s) promoted, %d with tech",
                len(results), promoted,
                sum(1 for h in ctx.alive_hosts
                    if isinstance(h, dict) and h.get("http_ok") is True))
        except Exception as e:
            logger.warning("httpx probe failed: %s", e)

    def _phase_probing(self, ctx: ScanContext) -> None:
        logger.info("[Phase 2] Probing: alive hosts")
        from modules.alive import check_alive
        # Always probe the apex: enumeration can return zero subdomains or
        # subdomains that all fail HTTP, which used to leave the scan with
        # no attack surface at all even though the root domain answered.
        probe_list = list(dict.fromkeys(
            [ctx.domain] + list(ctx.subdomains or [])))
        ctx.alive_hosts = self._safe("check_alive", check_alive, probe_list) or []
        logger.info("  -> %d alive hosts", len(ctx.alive_hosts))

        # httpx first: it repairs http_ok and seeds technologies.
        self._phase_httpx_first(ctx)

        if not ctx.alive_hosts:
            logger.warning("  No alive hosts; skipping port/header/tech scans")
            return

        # CDN detection pass: tag each host so we can skip port-scanning
        # any CDN-fronted target (scanning Cloudflare IPs gets us banned).
        from modules.cdn_detector import detect_cdn
        cdn_hosts = []
        for h in ctx.alive_hosts:
            if isinstance(h, dict):
                ip = h.get("ip")
                if ip:
                    cdn = detect_cdn(ip)
                    if cdn:
                        h["cdn"] = cdn
                        cdn_hosts.append((h.get("domain"), cdn))
        if cdn_hosts:
            logger.warning(
                "%d host(s) behind a CDN: %s",
                len(cdn_hosts),
                ", ".join(f"{d} ({c})" for d, c in cdn_hosts),
            )

        if not self.skip_ports:
            logger.info("[Phase 2] Probing: port scan (nmap)")
            from modules.ports import scan_ports
            # Skip port scanning for CDN-fronted hosts
            cdn_free = [h for h in ctx.alive_hosts
                        if not (isinstance(h, dict) and h.get("cdn"))]
            skipped = len(ctx.alive_hosts) - len(cdn_free)
            if skipped:
                logger.info("  port scan: skipping %d CDN-fronted host(s)", skipped)
            if cdn_free:
                ports_result = self._safe("scan_ports", scan_ports, cdn_free) or {}
                ctx.ports = ports_result if isinstance(ports_result, dict) else {}
            else:
                ctx.ports = {}
            # Emit risk events for open high-risk ports
            from modules.risk_scoring import HIGH_RISK_PORTS
            import re as _re
            for host, info in ctx.ports.items():
                for p in (info.get("open_ports") or []):
                    evt = {
                        "type": "OPEN_PORT",
                        "domain": host,
                        "port": p.get("port"),
                        "service": p.get("service"),
                        "banner": p.get("banner"),
                        "severity": "high" if p.get("port") in HIGH_RISK_PORTS else "medium",
                    }
                    ctx.add_event(evt)
                    # banner-driven intelligence (blue-team)
                    b = (p.get("banner") or "")
                    bl = b.lower()
                    if p.get("port") in (3306, 5432, 27017, 6379):
                        ctx.add_event({
                            "type": "DATABASE_PORT_EXPOSED",
                            "domain": host, "port": p.get("port"),
                            "banner": b, "severity": "critical",
                        })
                    m = _re.search(r"(\d+\.\d+(?:\.\d+)?)", b)
                    if m and p.get("port") in (21, 22, 25, 110, 143, 53):
                        ctx.add_event({
                            "type": "SERVICE_VERSION_BANNER",
                            "domain": host, "port": p.get("port"),
                            "banner": b, "version": m.group(1),
                            "severity": "info",
                        })
            logger.info("  -> ports for %d hosts", len(ctx.ports))
        else:
            logger.info("[Phase 2] Probing: port scan SKIPPED (--no-ports)")

        logger.info("[Phase 2] Probing: header audit")
        from modules.header_audit import audit_headers
        header_result = self._safe(
            "audit_headers", audit_headers, _web_hosts(ctx.alive_hosts)) or {}

        # Build the headers dict expected by the report + risk
        for host, info in header_result.items():
            ctx.headers[host] = {
                "url": info.get("url", f"https://{host}"),
                "status_code": info.get("status_code", 0),
                "issues": info.get("issues", []),
                "all_headers": info.get("all_headers", {}) or info.get("security_headers", {}),
                "security_headers": info.get("security_headers", {}),
                "error": info.get("error"),
            }
            # Emit events for each missing header
            for issue in info.get("issues", []):
                finding_key = _issue_to_finding_key(issue)
                if finding_key:
                    ctx.add_event({
                        "type": finding_key,
                        "domain": host,
                        "severity": "medium",
                    })
        logger.info("  -> headers for %d hosts", len(ctx.headers))

        logger.info("[Phase 2] Probing: technology fingerprint")
        from modules.tech_fingerprint import fingerprint_technologies
        tech_result = self._safe("fingerprint_technologies",
                                 fingerprint_technologies,
                                 _web_hosts(ctx.alive_hosts)) or {}
        for host, info in tech_result.items():
            # Never let an empty fingerprint result wipe what httpx already
            # discovered — CVE mapping reads ctx.technologies, and losing it
            # means losing every CVE we could have shown.
            seen_tech = info.get("technologies") or []
            if seen_tech:
                ctx.technologies[host] = seen_tech or []
        logger.info("  -> technologies for %d hosts", len(ctx.technologies))

        # Metasploit mapping: every exposed service with a version banner
        # gets a CHECK suggestion; confirmed-vuln versions get a chained
        # exploit+payload one-liner the operator can fire from the terminal.
        if ctx.ports and self.enable_msf_map:
            try:
                from modules.redteam import msf_map
                ctx.msf_suggestions = msf_map.map_hosts(ctx.alive_hosts, ctx.ports)
                if ctx.msf_suggestions:
                    logger.info("  -> %d Metasploit module suggestion(s)", len(ctx.msf_suggestions))
                    for s in ctx.msf_suggestions:
                        ctx.add_event({
                            "type": "MSF_SUGGESTION",
                            "domain": s["host"], "port": s["port"],
                            "module": s["module"], "stage": s["stage"],
                            "severity": "high" if s["stage"] == "exploit" else "medium",
                        })
            except Exception as e:
                logger.warning("msf service mapping failed: %s", e)

        # Did anything answer at all? A scan that reaches an unreachable
        # (or blocking) target produces ZERO findings — which must never
        # read as a clean bill of health. Record coverage explicitly.
        self._record_reachability(ctx)

        # nuclei (v0.23/v0.32): runs on the URLs httpx already proved live
        # in Phase 2.0 — re-probing them here would only double the cost.
        if (self.enable_nuclei or self.enable_httpx) and ctx.subdomains:
            try:
                from modules.httpx_nuclei import run_nuclei
                logger.info("[Phase 2.5] nuclei template scan")
                rows = getattr(ctx, "http_results", None) or []
                live = [r["url"] for r in rows if r.get("url")]
                if not live:
                    # httpx was throttled to zero — check_alive still knows
                    # which hosts answer, so scan those instead of skipping
                    # the whole template pass.
                    cand = _web_hosts(ctx.alive_hosts) or ctx.alive_hosts
                    live = [f"{(h.get('protocol') or 'https')}://{h.get('domain')}"
                            for h in cand
                            if isinstance(h, dict) and h.get("domain")]
                    if live:
                        logger.info("  -> httpx gave no URLs; falling back "
                                    "to %d check_alive host(s)", len(live))
                nuclei_findings = []
                if live:
                    nuclei_findings = self._safe(
                        "run_nuclei", run_nuclei, live,
                        severity=self.nuclei_severity, timeout=600,
                        # 14k templates x N hosts: at the old 10 r/s the
                        # sweep could never finish inside the budget.
                        rate_limit=50) or []
                ctx.nuclei_findings = nuclei_findings
                logger.info("  -> nuclei: %d findings %s",
                            len(nuclei_findings),
                            dict(Counter(f.get("severity", "info")
                                         for f in nuclei_findings)) or {})
                # Everything is stored (sections.nuclei drives the graph and
                # the advisor), but only medium+ enters the findings feed so
                # info-level tech detections cannot inflate the risk score.
                for f in nuclei_findings[:60]:
                    sev = str(f.get("severity") or "info").lower()
                    if sev not in ("medium", "high", "critical"):
                        continue
                    tag = sev.upper()
                    cve = f.get("cve") or ""
                    cve_tag = f" [{cve}]" if cve else ""
                    ctx.findings.setdefault(
                        f.get("url") or ctx.domain, []).append(
                        f"[{tag}] {f.get('name', 'finding')}{cve_tag} "
                        f"on {f.get('url', '')}")
                    ctx.add_event({
                        "type": "NUCLEI_FINDING",
                        "domain": ctx.domain,
                        "severity": ("critical" if sev == "critical"
                                     else "high" if sev == "high"
                                     else "medium"),
                    })
            except Exception as e:
                logger.warning("nuclei scan failed: %s", e)

    def _phase_admin_origin(self, ctx: ScanContext) -> None:
        if not self.skip_admin and _web_hosts(ctx.alive_hosts):
            logger.info("[Phase 3] Admin panel discovery")
            try:
                from modules.admin_finder import find_admin_panels
                admins = self._safe("find_admin_panels",
                                    find_admin_panels,
                                    _web_hosts(ctx.alive_hosts)) or {}
                if isinstance(admins, dict):
                    ctx.admin_panels = admins
                # Collect the "primary" admin panel for each host.
                # This is the panel most likely to actually control the
                # server (cPanel, WHM, Plesk, ...) as opposed to a
                # user-facing login form. Marked by find_admin_panels via
                # the is_primary flag.
                #
                # Dedup by final URL: many cPanel-related subdomains
                # (cpanel., cpcalendars., webdisk., webmail., ...) all
                # land on the same cPanel endpoint, so we'd otherwise
                # report it N times. We keep the FIRST hit and the
                # highest score for ties.
                seen_urls = {}
                for host, panels in ctx.admin_panels.items():
                    for p in panels:
                        if p.get("is_primary"):
                            url = p.get("url")
                            score = p.get("score", 0)
                            if url in seen_urls and seen_urls[url]["score"] >= score:
                                continue
                            seen_urls[url] = {
                                "domain": host,
                                "url": url,
                                "path": p.get("path"),
                                "port": (url.rsplit(":", 1)[-1].split("/")[0]
                                         if ":" in (url or "") else None),
                                "vendor": p.get("vendor", ""),
                                "score": score,
                                "protected": p.get("protected", True),
                                "cross_host_redirect": p.get("cross_host_redirect", False),
                            }
                # Sort by score desc, then by domain for stable output
                ctx.primary_admin_panels = sorted(
                    seen_urls.values(),
                    key=lambda x: (-x["score"], x["domain"]),
                )
                # Surface the deduped primaries as normalized events too
                for p in ctx.primary_admin_panels:
                    ctx.add_event({
                        "type": "PRIMARY_ADMIN_PANEL",
                        "domain": p["domain"],
                        "url": p["url"],
                        "vendor": p["vendor"],
                        "severity": "high" if not p["protected"] else "medium",
                    })
                # Emit events for exposed admin panels
                for host, panels in ctx.admin_panels.items():
                    for p in panels:
                        if p.get("panel_type") == "admin" and not p.get("protected"):
                            ctx.add_event({
                                "type": "ADMIN_PANEL_EXPOSED",
                                "domain": host,
                                "severity": "high",
                            })
                logger.info("  -> admin panels for %d hosts, %d primary",
                            len(ctx.admin_panels), len(ctx.primary_admin_panels))
            except Exception as e:
                logger.warning("admin_finder failed: %s", e)

        # Exposed CMS setup pages (WordPress install.php, ...) — CRITICAL
        if ctx.alive_hosts:
            logger.info("[Phase 3] CMS setup page detection")
            try:
                from modules.setup_page_detector import detect_setup_pages
                setups = self._safe("detect_setup_pages",
                                    detect_setup_pages, ctx.alive_hosts,
                                    rate_limiter=self.limiter) or {}
                if setups:
                    ctx.setup_pages = setups
                    for host, pages in setups.items():
                        for pg in pages:
                            ctx.add_event({
                                "type": "SETUP_PAGE_EXPOSED",
                                "domain": host,
                                "url": pg["url"],
                                "cms": pg["cms"],
                                "severity": "critical",
                            })
                    logger.warning("  -> %d host(s) with exposed setup pages!",
                                   len(setups))
            except ImportError:
                logger.warning("setup_page_detector not available")

        if not self.skip_origin and ctx.alive_hosts:
            logger.info("[Phase 3] Origin IP correlation")
            try:
                from modules.origin_ip_discovery import subdomain_ip_correlation
                origins = self._safe("subdomain_ip_correlation",
                                     subdomain_ip_correlation, ctx.alive_hosts) or []
                if isinstance(origins, list):
                    ctx.origin_ips = origins
                    for ev in origins:
                        ctx.add_event(ev)
                logger.info("  -> %d origin candidates", len(ctx.origin_ips))
            except Exception as e:
                logger.warning("origin_ip_discovery failed: %s", e)

    def _phase_analysis(self, ctx: ScanContext) -> None:
        logger.info("[Phase 4] Analysis: risk scoring")
        from modules.risk_scoring import calculate_risk
        risk_result = self._safe("calculate_risk", calculate_risk, ctx.events) or {}
        per_domain = risk_result.get("per_domain", {}) if isinstance(risk_result, dict) else {}
        ctx.risk_scores = per_domain
        logger.info("  -> risk scored for %d hosts", len(ctx.risk_scores))

        logger.info("[Phase 4] Analysis: attack paths")
        from modules.attack_path_engine import build_attack_paths
        ctx.attack_paths = self._safe("build_attack_paths",
                                      build_attack_paths, ctx) or []
        logger.info("  -> %d attack paths", len(ctx.attack_paths))

        logger.info("[Phase 4] Analysis: MITRE mapping")
        from modules.mitre_mapping import map_attack_paths_to_mitre
        mitre_list = self._safe("map_attack_paths_to_mitre",
                                map_attack_paths_to_mitre, ctx.attack_paths) or []
        if isinstance(mitre_list, list):
            for entry in mitre_list:
                host = entry.get("host") or entry.get("source_host")
                if host:
                    ctx.mitre_attack[host] = entry.get("techniques", [])
        logger.info("  -> MITRE for %d hosts", len(ctx.mitre_attack))

        logger.info("[Phase 4] Analysis: findings generation")
        from modules.correlation_engine import generate_findings
        for host in ctx.alive_hosts:
            domain = host.get("domain") if isinstance(host, dict) else host
            f = self._safe(
                "generate_findings",
                generate_findings,
                domain,
                risk=ctx.risk_scores.get(domain, {}),
                tech=ctx.technologies.get(domain, []),
                ports=ctx.ports.get(domain, {}).get("open_ports", []) if isinstance(ctx.ports.get(domain), dict) else [],
                misconf={"missing": ctx.headers.get(domain, {}).get("issues", [])},
            ) or []
            if f:
                ctx.findings[domain] = f
        logger.info("  -> findings for %d hosts", len(ctx.findings))

        logger.info("[Phase 4] Analysis: kill chain")
        from modules.kill_chain import build_kill_chain
        ctx.kill_chain = self._safe("build_kill_chain", build_kill_chain, ctx) or {}
        logger.info("  -> kill chain built")

    def _phase_visualization(self, ctx: ScanContext) -> None:
        logger.info("[Phase 5] Visualization: graph")
        try:
            from modules.graph_builder import build_attack_surface_graph
            self._safe("build_attack_surface_graph", build_attack_surface_graph, ctx)
        except Exception as e:
            logger.warning("graph_builder failed: %s", e)

        # Emit NDJSON summary event
        ndjson_emit({
            "type": "scan_summary",
            "target": ctx.domain,
            "alive_hosts": len(ctx.alive_hosts),
            "subdomains": len(ctx.subdomains),
            "findings": sum(len(v) for v in ctx.findings.values()),
            "attack_paths": len(ctx.attack_paths),
            "errors": len(ctx.errors),
        })

    def _phase_blue_team(self, ctx: ScanContext) -> None:
        """Baseline diff, takeover check, CVE watchlist, SOC telemetry."""
        from modules.baseline import load_baseline, save_baseline, diff
        logger.info("[Phase 5.5] Blue-team: baseline diff")
        try:
            prev = load_baseline(ctx.domain) if self.use_baseline else None
            if prev is not None:
                from modules.baseline import _snapshot
                delta = diff(_snapshot(ctx), prev)
                changed = any(delta.values())
                ctx.blue_team_diff = delta
                if changed:
                    logger.warning("  baseline CHANGED: %s",
                                   {k: len(v) for k, v in delta.items() if v})
                    for nh in delta.get("NEW_SETUP_PAGES", []):
                        ctx.add_event({"type": "SETUP_PAGE_EXPOSED",
                                       "domain": nh.get("host"),
                                       "url": nh.get("url"),
                                       "severity": "critical"})
                else:
                    logger.info("  baseline unchanged")
            if self.use_baseline:
                save_baseline(ctx)
        except Exception as e:
            logger.warning("baseline diff failed: %s", e)

        logger.info("[Phase 5.5] Blue-team: takeover check")
        try:
            from modules.takeover_check import check_takeover
            tk = self._safe("check_takeover", check_takeover,
                            ctx.alive_hosts, rate_limiter=self.limiter) or []
            if tk:
                ctx.takeover_risks = tk
                for f in tk:
                    ctx.add_event({"type": "SUBDOMAIN_TAKEOVER",
                                   "domain": f.get("host"),
                                   "service": f.get("service"),
                                   "severity": "critical"})
                logger.warning("  -> %d possible takeover(s)!", len(tk))
        except Exception as e:
            logger.warning("takeover check failed: %s", e)

        if self.cve_deep:
            logger.info("[Phase 5.5] Blue-team: CVE DEEP scan (CPE exact-match)")
            try:
                from modules.cve_deep import deep_scan
                _merge_cve_watchlist(ctx, self._safe(
                    "cve_deep", deep_scan, ctx.technologies) or {})
                _log_cve_total(ctx, "CVE DEEP (CPE)")
            except Exception as e:
                logger.warning("cve deep failed: %s", e)
        if self.critical_web:
            logger.info("[Phase 5.5] CRITICAL web checks: email spoof / misconfig / brand")
            try:
                from modules.email_security import check_email_security
                ctx.email_security = self._safe(
                    "email_sec", check_email_security, ctx.domain) or {}
                for f in ((ctx.email_security or {}).get("findings") or []):
                    ctx.add_event({"type": f.get("type"), "domain": ctx.domain,
                                   "severity": f.get("severity")})
                if (ctx.email_security or {}).get("email_spoofing_possible"):
                    logger.warning("  -> EMAIL SPOOFING POSSIBLE on %s!", ctx.domain)
            except Exception as e:
                logger.warning("email security check failed: %s", e)
            try:
                from modules.web_misconfig import run_checks
                ctx.web_misconfig = self._safe(
                    "web_misconfig", run_checks, ctx.alive_hosts,
                    rate_limiter=self.limiter) or []
                for f in ctx.web_misconfig:
                    ctx.add_event({"type": f.get("type"), "domain": f.get("domain"),
                                   "evidence": f.get("evidence"),
                                   "severity": f.get("severity")})
                if ctx.web_misconfig:
                    logger.warning("  -> %d misconfiguration(s) found!",
                                   len(ctx.web_misconfig))
            except Exception as e:
                logger.warning("web misconfig checks failed: %s", e)
            try:  # WordPress specialized recon (safe, read-only)
                from modules import wp_recon
                ctx.wp_recon = {}
                for h in (ctx.alive_hosts or [])[:6]:
                    host = h.get("domain") if isinstance(h, dict) else h
                    base = host if str(host).startswith("http") else f"https://{host}"
                    rec = self._safe("wp_recon", wp_recon.run_wp_recon, base) or {}
                    if rec.get("wordpress"):
                        ctx.wp_recon[host] = rec
                        fs = wp_recon.to_findings(host, rec)
                        if fs:
                            ctx.findings.setdefault(host, []).extend(fs)
                            logger.warning("  -> WordPress: %d issue(s) on %s",
                                           len(fs), host)
                if ctx.wp_recon:
                    logger.info("  -> WordPress recon: %d site(s)", len(ctx.wp_recon))
            except Exception as e:
                logger.warning("wp recon failed: %s", e)
            try:  # SAFE SQLi surface probe (error signatures only)
                from modules import sqli_probe
                ctx.sqli_probe = {}
                for h in (ctx.alive_hosts or [])[:4]:
                    host = h.get("domain") if isinstance(h, dict) else h
                    base = host if str(host).startswith("http") else f"https://{host}"
                    pr = self._safe("sqli_probe", sqli_probe.run_sqli_probe, base) or {}
                    if pr.get("candidates"):
                        ctx.sqli_probe[host] = pr
                        fs = sqli_probe.to_findings(host, pr)
                        if fs:
                            ctx.findings.setdefault(host, []).extend(fs)
                            logger.warning("  -> SQLi candidates on %s: %d",
                                           host, len(fs))
            except Exception as e:
                logger.warning("sqli probe failed: %s", e)
            try:
                from modules.domain_intel import run_checks as _rdi
                ctx.domain_intel = self._safe("domain_intel", _rdi, ctx.domain) or {}
                ct = (ctx.domain_intel or {}).get("ct") or {}
                for ent in (ct.get("new") or [])[:10]:
                    ctx.add_event({"type": "CT_NEW_CERTIFICATE", "domain": ent.get("name"),
                                   "severity": "medium"})
                for ent in (ct.get("lookalikes") or [])[:10]:
                    ctx.add_event({"type": "CT_LOOKALIKE_CERT", "domain": ent.get("name"),
                                   "severity": "high"})
            except Exception as e:
                logger.warning("domain intel failed: %s", e)

        # Independent feature, NOT chained to critical_web: this elif made
        # `--cves` dead code whenever the (default-on) critical web checks
        # ran, which is every scan — sections['cves'] was empty forever.
        if self.map_cves:
            logger.info("[Phase 5.5] Blue-team: CVE watchlist (NVD)")
            try:
                from modules.cve_mapper import map_cves
                _merge_cve_watchlist(ctx, self._safe(
                    "map_cves", map_cves, ctx.technologies) or {})
                _log_cve_total(ctx, "CVE watchlist (NVD)")
            except Exception as e:
                logger.warning("cve mapping failed: %s", e)

        if self.active_poc:
            logger.info("[Phase 5.5] Blue-team: ACTIVE PoC (tls/login/axfr) — safe mode")
            try:
                from modules.active_poc import run_all
                ctx.poc_results = self._safe(
                    "active_poc", run_all, ctx.alive_hosts,
                    ctx.domain, rate_limiter=self.limiter) or {}
                tls_bad = [t for t in ctx.poc_results.get("tls", []) if t.get("issues")]
                axfr = (ctx.poc_results.get("dns") or {}).get("axfr_allowed")
                if axfr:
                    ctx.add_event({"type": "DNS_ZONE_TRANSFER", "domain": ctx.domain,
                                   "severity": "high"})
                logger.info("  -> TLS graded hosts: %d, bad: %d, AXFR: %s",
                            len(ctx.poc_results.get("tls", [])), len(tls_bad), axfr)
            except Exception as e:
                logger.warning("active poc failed: %s", e)

        # NEW: Cloud Asset Discovery (conditional)
        if self.enable_cloud:
            logger.info("[Phase 5.5] Cloud asset discovery (AWS/Azure/GCP)")
            try:
                from modules.cloud import CloudDiscovery
                cloud = CloudDiscovery()
                ctx.cloud_assets = cloud.discover_all(ctx.domain)
                total_cloud = sum(len(v) for v in ctx.cloud_assets.values())
                logger.info("  -> %d cloud assets discovered", total_cloud)
            except Exception as e:
                logger.warning("cloud discovery failed: %s", e)

        # NEW: API Security Discovery (conditional)
        if self.enable_api_scan:
            logger.info("[Phase 5.5] API security discovery (OpenAPI/GraphQL/REST)")
            try:
                from modules.api import APIDiscovery, APIFuzzer
                api_disc = APIDiscovery(rate_limit=self.limiter._rate if hasattr(self.limiter, '_rate') else 1.0)
                # Use authenticated session if available
                api_endpoints = []
                for h in ctx.alive_hosts[:3]:
                    host = h.get("domain") if isinstance(h, dict) else h
                    base = host if str(host).startswith("http") else f"https://{host}"
                    api_endpoints.extend(api_disc.discover_openapi(base))
                    api_endpoints.extend(api_disc.discover_graphql(base))
                ctx.api_endpoints = api_endpoints
                logger.info("  -> %d API endpoints discovered", len(api_endpoints))

                # Fuzz endpoints
                if api_endpoints:
                    fuzzer = APIFuzzer()
                    fuzz_results = []
                    for ep in api_endpoints[:10]:
                        fuzz_results.extend(fuzzer.fuzz_endpoint(ep))
                    ctx.api_fuzz_results = fuzz_results
                    logger.info("  -> %d API fuzz findings", len(fuzz_results))
            except Exception as e:
                logger.warning("API security discovery failed: %s", e)

        # NEW: MITRE ATT&CK Mapping (conditional)
        if self.enable_mitre:
            logger.info("[Phase 5.5] MITRE ATT&CK mapping")
            try:
                from modules.mitre import MITREMapper
                mitre = MITREMapper()
                all_findings = []
                for host_findings in ctx.findings.values():
                    all_findings.extend(host_findings)
                ctx.mitre_coverage = mitre.analyze_coverage(all_findings)
                ctx.mitre_layer = mitre.generate_attack_navigator_layer(all_findings, ctx.domain)
                logger.info("  -> ATT&CK coverage: %s%% (%d/%d tactics)",
                            ctx.mitre_coverage["coverage_percent"],
                            len(ctx.mitre_coverage["covered_tactics"]), len(TACTICS))
            except Exception as e:
                logger.warning("MITRE mapping failed: %s", e)

        # NEW: SBOM Analysis (conditional)
        if self.sbom_file:
            logger.info("[Phase 5.5] SBOM supply chain analysis")
            try:
                from modules.sbom import SBOMAnalyzer
                analyzer = SBOMAnalyzer()
                ctx.sbom_analysis = analyzer.parse_sbom(self.sbom_file)
                logger.info("  -> %d dependencies, %d vulnerabilities",
                            ctx.sbom_analysis.total_deps,
                            ctx.sbom_analysis.vulnerable_deps)
            except Exception as e:
                logger.warning("SBOM analysis failed: %s", e)

        # NEW: Authenticated Scanning (conditional)
        if self.auth_config:
            logger.info("[Phase 5.5] Authenticated scanning setup")
            try:
                from modules.auth import AuthManager
                auth = AuthManager()
                # If auth_config is a file, we could load it here
                session = auth.get_auth_session("default")
                ctx.auth_session = session
                logger.info("  -> Auth session ready: %s", "yes" if session else "no")
            except Exception as e:
                logger.warning("Auth setup failed: %s", e)

        # NEW: Red Team Action Mapping (conditional)
        if self.enable_redteam:
            logger.info("[Phase 5.5] Red Team action mapping")
            try:
                from modules.redteam import create_redteam_orchestrator
                redteam = create_redteam_orchestrator()
                ctx.redteam_actions = []
                for host, flist in (ctx.findings or {}).items():
                    for finding in flist or []:
                        # findings may be plain strings — normalize to dicts
                        fdict = (finding if isinstance(finding, dict)
                                 else {"title": str(finding)})
                        fdict.setdefault("host", host)
                        actions = redteam.map_finding_to_actions(fdict)
                        ctx.redteam_actions.extend(actions)
                logger.info("  -> %d red team actions mapped", len(ctx.redteam_actions))
            except Exception as e:
                logger.warning("Red team mapping failed: %s", e)

        # Feed the CVE watchlist into the risk engine, then re-score.
        # Phase 4 computed risk BEFORE this phase, so everything blue-team
        # produced — email spoofing, takeover, and the CVE watchlist — was
        # invisible to the score. (That is also why a scan with 10 CVEs
        # scored 23 while one with none scored 66.)
        self._emit_cve_events(ctx)
        self._rescore_after_blue_team(ctx)
        self._run_asm(ctx)

        # SOC telemetry
        if ctx.events and (self.syslog_target or self.webhook_url or self.telegram_token):
            logger.info("[Phase 5.5] Blue-team: SOC telemetry")
            try:
                from modules import telemetry
                if self.syslog_target:
                    host, _, port = self.syslog_target.partition(":")
                    n = telemetry.send_syslog(ctx.events, host,
                                              int(port) if port else 514)
                    logger.info("  syslog: %d events sent", n)
                if self.webhook_url:
                    n = telemetry.push_webhook(ctx.events, self.webhook_url)
                    logger.info("  webhook: %d alerts", n)
                if self.telegram_token and self.telegram_chat:
                    n = telemetry.push_telegram(ctx.events, self.telegram_token,
                                                self.telegram_chat)
                    logger.info("  telegram: %d alerts", n)
            except Exception as e:
                logger.warning("telemetry failed: %s", e)

    @staticmethod
    def _record_reachability(ctx: ScanContext) -> None:
        """Note whether the target answered anything, and say so out loud.

        Distinguishes three states so '0 findings' can be interpreted:
          reachable  — at least one host answered HTTP,
          no_web     — ports are open but no HTTP service answered,
          unreachable — neither HTTP nor open ports (filtered/down).
        """
        hosts = [h for h in (ctx.alive_hosts or []) if isinstance(h, dict)]
        web = [h for h in hosts if h.get("http_ok") is True]
        ports = getattr(ctx, "ports", None) or {}
        open_port_count = 0
        if isinstance(ports, dict):
            for row in ports.values():
                if isinstance(row, dict):
                    open_port_count += len(row.get("open_ports") or [])
        if web or getattr(ctx, "http_results", None):
            state, note = "reachable", ""
        elif open_port_count:
            state = "no_web"
            note = (f"no HTTP service answered, but {open_port_count} port(s) "
                    f"are open — web-phase coverage is incomplete")
        else:
            state = "unreachable"
            note = ("target answered neither HTTP nor any port probe — "
                    "the host is filtered, down, or blocking this source; "
                    "treat this scan as INCOMPLETE, not clean")
        ctx.reachability = {
            "state": state,
            "reachable": state == "reachable",
            "http_hosts": len(web),
            "hosts_checked": len(hosts),
            "open_ports": open_port_count,
            "note": note,
        }
        if state != "reachable":
            logger.warning("  -> reachability: %s — %s", state, note)
            ctx.findings.setdefault(ctx.domain, []).append(
                f"**Scan Coverage**: {state.upper()} — {note} (high)")

    def _run_asm(self, ctx: ScanContext) -> None:
        """Continuous ASM: asset inventory + change alerts.

        --asm existed since v0.19 and was stored but never read, so the
        module never ran. DeltaScanner compares this scan against the last
        snapshot it saved and reports what appeared/disappeared.
        """
        if not self.enable_asm:
            return
        logger.info("[Phase 5.5] ASM: asset inventory + delta scan")
        try:
            from modules.asm import ASMDatabase, DeltaScanner
            from pathlib import Path

            # tests inject their own database here
            db_path = getattr(self, "asm_db_path", None)
            ports_by_host = getattr(ctx, "ports", None) or {}
            hosts = []
            for h in (ctx.alive_hosts or []):
                if not isinstance(h, dict):
                    continue
                name = h.get("domain") or ""
                row = (ports_by_host.get(name)
                       if isinstance(ports_by_host, dict) else None)
                hosts.append({"host": name, "ip": h.get("ip"),
                              "ports": (row or {}).get("open_ports") or []})
            findings = []
            for host, items in (ctx.findings or {}).items():
                for f in (items or []):
                    findings.append({
                        "host": host,
                        "finding": (f if isinstance(f, str) else str(f))[:200]})
            scan_results = {
                "subdomains": list(ctx.subdomains or []),
                "hosts": hosts,
                "technologies": getattr(ctx, "technologies", None) or {},
                "findings": findings,
            }
            db = ASMDatabase(Path(db_path)) if db_path else ASMDatabase()
            changes = self._safe(
                "asm", DeltaScanner(db).process_scan,
                int(getattr(ctx, "scan_id", 0) or 0), ctx.domain,
                scan_results, self.scope) or []
            ctx.asm_changes = changes
            if changes:
                logger.warning(
                    "  -> %d surface change(s): %s", len(changes),
                    ", ".join(f"{c.get('type')}:"
                              f"{c.get('value', c.get('data'))}"
                              for c in changes[:5]))
            else:
                logger.info("  -> no surface change since the last snapshot")
        except Exception as e:
            logger.warning("asm failed: %s", e)
            ctx.asm_changes = []

    @staticmethod
    def _emit_cve_events(ctx: ScanContext) -> None:
        """Turn CVE watchlist rows into scored events (type CVE_WATCHLIST)."""
        try:
            watch = getattr(ctx, "cve_watchlist", None) or {}
            for host, rows in watch.items():
                if not isinstance(rows, list):
                    continue
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    exact = row.get("match") == "cpe_exact"
                    for c in (row.get("cves") or [])[:10]:
                        if not isinstance(c, dict):
                            continue
                        cid = c.get("id") or c.get("cve")
                        if not cid:
                            continue
                        try:
                            cvss = float(c.get("cvss") or 0)
                        except (TypeError, ValueError):
                            cvss = 0.0
                        severity = ("critical" if cvss >= 9 else
                                    "high" if cvss >= 7 else
                                    "medium" if cvss >= 4 else "low")
                        ctx.add_event({
                            "type": "CVE_WATCHLIST",
                            "domain": host,
                            "cve": str(cid),
                            "cvss": cvss,
                            "kev": bool(c.get("kev")),
                            "exact": exact,
                            "severity": severity,
                        })
        except Exception as e:
            logger.warning("cve event emit failed: %s", e)

    def _rescore_after_blue_team(self, ctx: ScanContext) -> None:
        """Recompute risk now that blue-team evidence exists."""
        try:
            from modules.risk_scoring import calculate_risk
            res = self._safe("calculate_risk", calculate_risk,
                             ctx.events) or {}
            per = res.get("per_domain") if isinstance(res, dict) else None
            if per:
                ctx.risk_scores = per
                logger.info("[Phase 5.5] Risk re-scored with blue-team "
                            "evidence -> overall %s (%s)",
                            res.get("overall_score"),
                            res.get("overall_level"))
            else:
                logger.warning("risk re-score produced nothing — keeping "
                               "phase-4 scores")
        except Exception as e:
            logger.warning("risk re-score failed: %s", e)

    def _phase_export(self, ctx: ScanContext) -> str:
        logger.info("[Phase 6] Export: reports")
        results = ctx.to_report_dict()

        # HTML
        html_path = ""
        try:
            from modules.report import generate_html_report
            html_path = generate_html_report(results) or ""
        except Exception as e:
            logger.warning("HTML report failed: %s", e)

        # CSV + Markdown
        try:
            import os
            os.makedirs("reports", exist_ok=True)
            os.makedirs("reports/html", exist_ok=True)
            from modules.exporter import export_csv, export_markdown, export_json
            export_csv(results, "reports/output.csv")
            export_markdown(results, "reports/output.md")
            export_json(results, "reports/output.json")
            # Kali interop: Metasploit/Zenmap can db_import this
            try:
                from modules.exporter import export_nmap_xml
                export_nmap_xml(results, "reports/output.xml")
            except Exception as _e:
                logger.debug("nmap-xml export skipped: %s", _e)
        except Exception as e:
            logger.warning("CSV/MD export failed: %s", e)

        return html_path

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def _checkpoint(self, ctx, phase_name: str) -> None:
        """Save a checkpoint if a path is configured. Never raises."""
        if not self.checkpoint_path:
            return
        # Mark the phase as completed on the ctx so we can skip it on resume
        if not hasattr(ctx, "_completed_phases"):
            ctx._completed_phases = []
        ctx._completed_phases.append(phase_name)
        from core.checkpoint import save_checkpoint
        save_checkpoint(ctx, self.checkpoint_path)
        logger.debug("Checkpoint after %s -> %s", phase_name, self.checkpoint_path)

    # Mapping: pipeline phase -> checkpoint data-field names.
    # A pipeline phase counts as "done" when ANY of its fields
    # is already populated in the checkpoint.
    PHASE_DATA_MAP = {
        "discovery": ("subdomains", "mx_records", "historical_dns"),
        "probing": ("alive_hosts", "ports", "headers", "technologies"),
        "admin_origin": ("admin_panels", "primary_admin_panels", "origin_ips"),
        "analysis": ("risk_scores", "attack_paths", "mitre_attack", "kill_chain", "findings"),
        "visualization": ("attack_paths",),
    }

    def _maybe_resume(self, ctx) -> set:
        """
        Load a checkpoint (if configured) and merge its data into `ctx`.
        Returns the set of pipeline phases that were already completed in
        the checkpoint so the caller can skip them.
        """
        from core.checkpoint import load_checkpoint
        if not self.resume_from:
            return set()
        cp = load_checkpoint(self.resume_from)
        if cp is None:
            logger.warning("Resume file %s missing or invalid; starting fresh", self.resume_from)
            return set()
        # Merge saved state into the current ctx (saved wins for already-done data)
        ctx.domain = cp.domain or ctx.domain
        ctx.subdomains = cp.subdomains or ctx.subdomains
        ctx.alive_hosts = cp.alive_hosts or ctx.alive_hosts
        ctx.ports = cp.ports or ctx.ports
        ctx.headers = cp.headers or ctx.headers
        ctx.technologies = cp.technologies or ctx.technologies
        ctx.admin_panels = cp.admin_panels or ctx.admin_panels
        ctx.primary_admin_panels = cp.primary_admin_panels or ctx.primary_admin_panels
        ctx.origin_ips = cp.origin_ips or ctx.origin_ips
        ctx.risk_scores = cp.risk_scores or ctx.risk_scores
        ctx.attack_paths = cp.attack_paths or ctx.attack_paths
        ctx.mitre_attack = cp.mitre_attack or ctx.mitre_attack
        ctx.kill_chain = cp.kill_chain or ctx.kill_chain
        ctx.findings = cp.findings or ctx.findings
        done = {
            phase for phase, fields in self.PHASE_DATA_MAP.items()
            if any(getattr(cp, f, None) for f in fields)
        }
        if done:
            logger.info("Resumed from %s: %d phase(s) already done",
                        self.resume_from, len(done))
        return done

    def run_full_scan(self, domain: str):
        """
        Run the full scan pipeline and return the populated ScanContext.

        This is the only public method the CLI should call.
        """
        domain = sanitize_domain(domain)
        ctx = ScanContext(domain=domain)

        # Scope validation (strict mode aborts here)
        if self.scope is not None:
            try:
                self.scope.validate_primary()
            except Exception as e:
                logger.error("Scope violation: %s", e)
                ctx.add_error("scope", str(e))
                raise

        # Resume support: figure out which phases we can skip
        done = self._maybe_resume(ctx)

        logger.info("=" * 60)
        logger.info("Attack Surface Scanner %s", ctx.version)
        logger.info("Target: %s", domain)
        logger.info("Rate limiter: %s", self.limiter)
        logger.info("Scope: %s", self.scope)
        logger.info("=" * 60)

        init_ndjson()
        ndjson_emit({"type": "scan_start", "target": domain, "version": ctx.version})

        try:
            if "discovery" not in done:
                self._phase_discovery(ctx); self._checkpoint(ctx, "discovery")
            else:
                logger.info("[Phase 1] Discovery: SKIPPED (resumed)")
            if "probing" not in done:
                self._phase_probing(ctx); self._checkpoint(ctx, "probing")
            else:
                logger.info("[Phase 2] Probing: SKIPPED (resumed)")
            if "admin_origin" not in done:
                self._phase_admin_origin(ctx); self._checkpoint(ctx, "admin_origin")
            else:
                logger.info("[Phase 3] Admin/Origin: SKIPPED (resumed)")
            if "analysis" not in done:
                self._phase_analysis(ctx); self._checkpoint(ctx, "analysis")
            else:
                logger.info("[Phase 4] Analysis: SKIPPED (resumed)")
            if "visualization" not in done:
                self._phase_visualization(ctx); self._checkpoint(ctx, "visualization")
            else:
                logger.info("[Phase 5] Visualization: SKIPPED (resumed)")
            self._phase_blue_team(ctx); self._checkpoint(ctx, "blue_team")
            # Always re-export (cheap and the user just asked for a report)
            self._phase_export(ctx)
        finally:
            ndjson_emit({"type": "scan_end", "target": domain, "errors": len(ctx.errors)})
            close_ndjson()

        # Print rate-limiter stats so the user knows what the throttle cost
        stats = self.limiter.stats  # @property -> dict
        logger.info("Rate limiter: %d reqs, %.1fms total wait",
                    stats.get("total_acquired", 0), stats.get("total_waited_ms", 0.0))

        logger.info("=" * 60)
        logger.info("Scan complete. Errors: %d", len(ctx.errors))
        logger.info("=" * 60)
        return ctx


def _issue_to_finding_key(issue: str):
    """
    Map a header_audit issue string to a finding key used by risk_scoring
    and payload_intelligence.
    """
    if not issue:
        return None
    i = issue.lower()
    if "content-security-policy" in i or "csp" in i:
        return "MISSING_CSP"
    if "hsts" in i or "strict-transport-security" in i:
        return "MISSING_HSTS"
    if "x-frame-options" in i:
        return "MISSING_X_FRAME_OPTIONS"
    if "x-content-type-options" in i or "nosniff" in i:
        return "MISSING_X_CONTENT_TYPE_OPTIONS"
    if "referrer-policy" in i:
        return "MISSING_REFERRER_POLICY"
    return None
