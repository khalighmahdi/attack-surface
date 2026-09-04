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
import traceback
from typing import Optional

from core.context import ScanContext
from core.stream import ndjson_emit, init_ndjson, close_ndjson
from core.utils import sanitize_domain

logger = logging.getLogger("AttackSurface.Runner")


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
    ):
        self.cve_deep = cve_deep
        self.active_poc = active_poc
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

    def _phase_probing(self, ctx: ScanContext) -> None:
        logger.info("[Phase 2] Probing: alive hosts")
        from modules.alive import check_alive
        ctx.alive_hosts = self._safe("check_alive", check_alive, ctx.subdomains) or []
        logger.info("  -> %d alive hosts", len(ctx.alive_hosts))

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
        header_result = self._safe("audit_headers", audit_headers, ctx.alive_hosts) or {}

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
                                 fingerprint_technologies, ctx.alive_hosts) or {}
        for host, info in tech_result.items():
            ctx.technologies[host] = info.get("technologies", []) or []
        logger.info("  -> technologies for %d hosts", len(ctx.technologies))

    def _phase_admin_origin(self, ctx: ScanContext) -> None:
        if not self.skip_admin and ctx.alive_hosts:
            logger.info("[Phase 3] Admin panel discovery")
            try:
                from modules.admin_finder import find_admin_panels
                admins = self._safe("find_admin_panels",
                                    find_admin_panels, ctx.alive_hosts) or {}
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
                ctx.cve_watchlist = self._safe(
                    "cve_deep", deep_scan, ctx.technologies) or {}
                total = sum(len(h.get("cves", []))
                            for v in ctx.cve_watchlist.values() for h in v)
                logger.info("  -> %d exact CVE(s)", total)
            except Exception as e:
                logger.warning("cve deep failed: %s", e)
        elif self.map_cves:
            logger.info("[Phase 5.5] Blue-team: CVE watchlist (NVD)")
            try:
                from modules.cve_mapper import map_cves
                ctx.cve_watchlist = self._safe(
                    "map_cves", map_cves, ctx.technologies) or {}
                total = sum(len(h.get("cves", []))
                            for v in ctx.cve_watchlist.values() for h in v)
                logger.info("  -> %d CVE(s) on watchlist", total)
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
