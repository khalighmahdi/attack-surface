#!/usr/bin/env python3
"""
attack_surface.py
==================
Unified CLI entry point for the Attack Surface Scanner.

Usage:
    python attack_surface.py -d example.com
    python attack_surface.py -d example.com --no-ports --no-admin
    python attack_surface.py -d example.com --update

The orchestrator lives in core/runner.py. This file is intentionally
thin: argument parsing, logging setup, and a clean summary at the end.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

from core.version import __version__


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # Quiet down noisy libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="attack_surface",
        description="Attack Surface Discovery & Analysis Tool",
    )
    p.add_argument("-d", "--domain", help="Target domain (e.g. example.com)")
    p.add_argument(
        "--no-ports", action="store_true",
        help="Skip port scanning (faster, no nmap required)",
    )
    p.add_argument(
        "--no-admin", action="store_true",
        help="Skip admin panel discovery",
    )
    p.add_argument(
        "--no-mx", action="store_true",
        help="Skip MX record discovery",
    )
    p.add_argument(
        "--no-historical", action="store_true",
        help="Skip historical DNS discovery (crt.sh)",
    )
    p.add_argument(
        "--no-origin", action="store_true",
        help="Skip origin IP correlation",
    )
    p.add_argument(
        "--max-subdomains", type=int, default=50,
        help="Cap subdomain enumeration to avoid runaway scans (default: 50)",
    )
    p.add_argument(
        "--rate", type=float, default=5.0,
        help="Max HTTP requests per second to the target (default: 5). "
             "Lower this if you hit a WAF or get rate-limited.",
    )
    p.add_argument(
        "--burst", type=int, default=10,
        help="Token-bucket burst size (default: 10). The scanner can save up "
             "to this many tokens when idle, then spend them in a burst.",
    )
    p.add_argument(
        "--no-throttle", action="store_true",
        help="Disable rate limiting (very fast, but risks WAF bans).",
    )
    p.add_argument(
        "--scope", type=str, default=None,
        help="Path to a scope file: one allowed domain (or suffix) per line. "
             "If omitted, only the exact -d domain is considered in-scope.",
    )
    p.add_argument(
        "--resume", type=str, default=None,
        help="Resume from a previous scan's checkpoint file (.json).",
    )
    p.add_argument(
        "--checkpoint", type=str, default="reports/checkpoint.json",
        help="Where to write the resume checkpoint (default: "
             "reports/checkpoint.json). Use --no-checkpoint to disable.",
    )
    p.add_argument(
        "--no-checkpoint", action="store_true",
        help="Disable checkpoint writing (useful for ephemeral scans).",
    )
    p.add_argument(
        "--no-baseline", action="store_true",
        help="Disable blue-team baseline diff (reports/baselines/)",
    )
    p.add_argument(
        "--syslog", type=str, default=None, metavar="HOST[:PORT]",
        help="Stream findings as CEF syslog to a SIEM collector",
    )
    p.add_argument(
        "--webhook", type=str, default=None,
        help="Push high/critical alerts to a Slack-compatible webhook",
    )
    p.add_argument(
        "--tg-token", type=str, default=None,
        help="Telegram bot token for on-call alerts",
    )
    p.add_argument(
        "--tg-chat", type=str, default=None,
        help="Telegram chat ID for on-call alerts",
    )
    p.add_argument(
        "--cves", action="store_true",
        help="Map fingerprinted technologies to known CVEs (NVD keyword API)",
    )
    p.add_argument(
        "--cves-deep", action="store_true",
        help="Precise CPE-based CVE matching with exact versions (NVD CPE API)",
    )
    p.add_argument(
        "--no-critical-web", action="store_true",
        help="Skip critical web checks (email spoofing, misconfig, brand watch)",
    )
    p.add_argument(
        "--poc", action="store_true",
        help="SAFE active probes: TLS audit, login liveness (1 attempt), DNS AXFR+DNSSEC",
    )
    # NEW: Advanced modules (v0.19)
    p.add_argument(
        "--asm", action="store_true",
        help="Enable Continuous ASM: asset inventory + delta scanning + change alerts",
    )
    p.add_argument(
        "--cloud", action="store_true",
        help="Enable cloud asset discovery (AWS/Azure/GCP)",
    )
    p.add_argument(
        "--api-scan", action="store_true",
        help="Enable API security discovery (OpenAPI/GraphQL/REST) + fuzzing",
    )
    p.add_argument(
        "--auth", type=str, default=None, metavar="CONFIG_FILE",
        help="Authenticated scanning config (cookies, tokens, headers) JSON/YAML file",
    )
    p.add_argument(
        "--sbom", type=str, default=None, metavar="SBOM_FILE",
        help="Supply chain scan: SBOM file (SPDX/CycloneDX/Syft) to analyze",
    )
    p.add_argument(
        "--mitre", action="store_true",
        help="Enable MITRE ATT&CK mapping + Navigator layer generation",
    )
    p.add_argument(
        "--report", type=str, default=None, choices=["executive", "technical", "compliance", "all"],
        help="Generate advanced report (executive/technical/compliance/all)",
    )
    p.add_argument(
        "--integrations", type=str, default=None, metavar="CONFIG_FILE",
        help="Integrations config (Jira/GitHub/SIEM/ChatOps/RBAC) JSON/YAML file",
    )
    p.add_argument(
        "--redteam", action="store_true",
        help="Enable Red Team action mapping (credential, exploit, lateral, AD, cloud, C2)"
    )
    p.add_argument(
        "--msf-map", action="store_true",
        help="Map exposed services to Metasploit modules (check-then-payload chains)"
    )
    p.add_argument(
        "--httpx", action="store_true",
        help="HTTP probing with httpx (live HTTP inventory: status, title, tech, CDN)"
    )
    p.add_argument(
        "--nuclei", action="store_true",
        help="Template-based vulnerability scan with nuclei (CVE/misconfig/exposure)"
    )
    p.add_argument(
        "--nuclei-severity", type=str, default="info,low,medium,high,critical",
        help="Nuclei severity filter (default: all severities — detections "
             "like an exposed wp-admin/install.php page report as info; the "
             "report still triages medium+ as the actionable tier)"
    )
    p.add_argument(
        "--pdf", action="store_true",
        help="Generate executive PDF report (reports/output_<domain>.pdf)",
    )
    p.add_argument(
        "--db-path", type=str, default=None,
        help="SQLite path for central scan history (default ~/.attack_surface/attacksurface.db)",
    )
    p.add_argument(
        "--list-scans", action="store_true",
        help="List stored scans from the database and exit",
    )
    p.add_argument(
        "--compare", type=int, nargs=2, metavar=("ID_A", "ID_B"),
        help="Diff two stored scans (new/gone subdomains & findings, score delta)",
    )
    p.add_argument(
        "--hunt-plan", action="store_true",
        help="After scan: generate hunt plan (reports/hunt_<domain>.md + targets + msf rc) "
             "mapping each finding to its specialized attack tool",
    )
    p.add_argument(
        "--auto-hunt", action="store_true",
        help="After scan: auto-RUN only SAFE non-destructive verifications "
             "(nuclei/curl/dig/testssl class). Active tools stay plan-only.",
    )
    p.add_argument(
        "--wordlist", type=str, default=None,
        help="Custom subdomain wordlist (Kali paths auto-detected)",
    )
    p.add_argument(
        "command", nargs="?", default=None, choices=["serve", "watch"],
        help="serve: live web dashboard | watch: scheduled diff-scan daemon",
    )
    p.add_argument(
        "--port", type=int, default=8443, help="Dashboard port (serve)"
    )
    p.add_argument(
        "--host", type=str, default="127.0.0.1",
        help="Dashboard bind address (serve). Use 0.0.0.0 inside containers "
             "so published ports are reachable; default is loopback-only."
    )
    p.add_argument(
        "--every", type=int, default=21600,
        help="watch: seconds between scans (default 21600 = 6h)",
    )
    p.add_argument(
        "--tg-alert", action="store_true",
        help="watch: telegram-alert on new findings/subdomains (needs --tg-token/--tg-chat or env)",
    )
    p.add_argument(
        "--config", type=str, default=None,
        help="Path to config.yaml (defaults: ~/.config/attack-surface/)",
    )
    p.add_argument(
        "--update", action="store_true",
        help="Check for and apply updates via git, then exit",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable debug logging",
    )
    return p


def do_update() -> int:
    """Best-effort self-update via git."""
    try:
        from modules.updater import check_for_updates
    except ImportError as e:
        print(f"[!] Cannot import updater: {e}")
        return 1
    # Use the runner's version as the "current" version
    try:
        from core.context import ScanContext
        current_version = ScanContext(domain="x").version.lstrip("v")
    except Exception:
        current_version = __version__
    check_for_updates(current_version)
    return 0


def print_summary(ctx) -> None:
    """Pretty-print a one-screen summary of the scan."""
    print()
    print("=" * 60)
    print(f"  Attack Surface Scan — {ctx.domain}")
    print("=" * 60)
    print(f"  Version          : {ctx.version}")
    print(f"  Scan time        : {ctx.scan_time}")
    print(f"  Subdomains       : {len(ctx.subdomains)}")
    print(f"  Alive hosts      : {len(ctx.alive_hosts)}")
    print(f"  Hosts w/ ports   : {len(ctx.ports)}")
    print(f"  Hosts w/ headers : {len(ctx.headers)}")
    print(f"  Admin panels     : {sum(len(v) for v in ctx.admin_panels.values())}")
    print(f"  Primary panels   : {len(ctx.primary_admin_panels)}")
    if ctx.primary_admin_panels:
        print()
        print("  Primary admin panel(s):")
        for p in ctx.primary_admin_panels:
            vendor = f" [{p.get('vendor')}]" if p.get('vendor') else ""
            xhost = "  (cross-host redirect)" if p.get('cross_host_redirect') else ""
            print(f"    -> {p.get('url')}{vendor}{xhost}")
    print(f"  Origin candidates: {len(ctx.origin_ips)}")
    print(f"  Findings         : {sum(len(v) for v in ctx.findings.values())}")
    print(f"  Attack paths     : {len(ctx.attack_paths)}")
    print(f"  MITRE techniques : {sum(len(v) for v in ctx.mitre_attack.values())}")
    print(f"  Errors           : {len(ctx.errors)}")
    print()

    # Risk overview
    if ctx.risk_scores:
        from core.term import risk_bar
        print("  Risk by host:")
        for host, info in ctx.risk_scores.items():
            if isinstance(info, dict):
                level = info.get("level", "?")
                score = info.get("score", 0)
                bar = risk_bar(score)
                print(f"    - {host:40s} {level:8s} {bar}")
        print()

    # Top findings
    if ctx.findings:
        print("  Top findings:")
        shown = 0
        for host, items in ctx.findings.items():
            for f in items:
                print(f"    [{host}] {f[:80]}")
                shown += 1
                if shown >= 5:
                    break
            if shown >= 5:
                break
        if shown:
            print()

    # Reports
    print("  Reports:")
    print(f"    - reports/html/report_*.html")
    print(f"    - reports/output.csv")
    print(f"    - reports/output.md")
    print(f"    - reports/graph_data.json")
    print("=" * 60)


def _watch_loop(args) -> int:
    """Scheduled differential scan daemon: scan every --every seconds,
    alert on new subs/findings (CLI + optional Telegram)."""
    import time as _t
    import db_store
    from core.utils import sanitize_domain

    if not args.domain:
        print("watch: -d <domain> required")
        return 2
    domain = sanitize_domain(args.domain)
    interval = max(300, args.every)
    print(f"[watch] target={domain} every={interval}s  Ctrl+C to stop")
    if args.tg_alert and not (os.environ.get("TG_TOKEN") or args.tg_token):
        print("[watch] warning: --tg-alert set but no TG_TOKEN env / --tg-token")

    def tg(msg: str) -> None:
        token = os.environ.get("TG_TOKEN") or args.tg_token
        chat = os.environ.get("TG_CHAT") or args.tg_chat
        if not (args.tg_alert and token and chat):
            return
        try:
            import urllib.request
            req = urllib.request.Request(
                f"https://api.telegram.org/bot{token}/sendMessage",
                data=json.dumps({"chat_id": chat, "text": msg}).encode(),
                headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10)
        except Exception as e:
            logging.warning("tg alert failed: %s", e)

    prev_subs: set[str] | None = None
    prev_find: set[tuple[str, str]] | None = None
    while True:
        rc = _run_scan_blocking(args, domain)
        data = None
        scans = db_store.list_scans(getattr(args, "db_path", None))
        if scans:
            data = db_store.get_scan(scans[0]["id"],
                                     getattr(args, "db_path", None))
        if data:
            subs = set(data["subdomains"] or [])
            finds = {(h, str(f)[:80]) for h, fl in (data["findings"] or {}).items()
                     for f in (fl or [])}
            if prev_subs is not None:
                new_subs = subs - prev_subs
                new_finds = finds - prev_find
                if new_subs or new_finds:
                    msg = (f"🛡️ attack-surface [{domain}]\n"
                           f"+ new subdomains: "
                           f"{', '.join(sorted(new_subs)) or '-'}\n"
                           f"+ new findings: "
                           f"{'; '.join(f'{h}: {t}' for h, t in sorted(new_finds)) or '-'}")
                    print(msg)
                    tg(msg)
                else:
                    print(f"[watch] {domain}: no change")
            prev_subs, prev_find = subs, finds
        try:
            _t.sleep(interval)
        except KeyboardInterrupt:
            print("\n[watch] stopped")
            return 0


def _run_scan_blocking(args, domain: str) -> int:
    """One scan cycle for watch: re-exec the CLI as a subprocess (clean state)."""
    import subprocess as _sp
    cmd = [sys.executable, os.path.abspath(__file__),
           "-d", domain, "--max-subdomains", str(args.max_subdomains or 30),
           "--rate", str(args.rate or 4)]
    if args.db_path:
        cmd += ["--db-path", args.db_path]
    try:
        p = _sp.run(cmd, capture_output=True, text=True, timeout=3600)
        if p.returncode != 0:
            logging.error("watch scan rc=%s: %s", p.returncode, p.stderr[-500:])
        return p.returncode
    except Exception as e:
        logging.error("watch scan failed: %s", e)
        return 1


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(verbose=args.verbose)
    try:
        from core.config import load_config, apply_to_args
        apply_to_args(args, load_config(getattr(args, "config", None)))
    except Exception:
        pass  # config optional

    # --update is a special case: no domain required
    if args.update:
        return do_update()

    # serve / watch commands (no domain required; watch uses -d as target)
    if getattr(args, "command", None) == "serve":
        from modules.dashboard import serve
        serve(host=getattr(args, "host", "127.0.0.1") or "127.0.0.1",
              port=args.port,
              db_path=getattr(args, "db_path", None))
        return 0

    if getattr(args, "command", None) == "watch":
        return _watch_loop(args)

    # DB helper commands (no domain needed)
    if getattr(args, "list_scans", False):
        import db_store
        rows = db_store.list_scans(getattr(args, "db_path", None))
        if not rows:
            print("No stored scans yet.")
            return 0
        print(f"{'ID':>4}  {'Timestamp':<20} {'Domain':<28} {'Score':>6}  Level")
        for r in rows:
            print(f"{r['id']:>4}  {r['ts']:<20} {r['domain']:<28} "
                  f"{(r['risk_score'] if r['risk_score'] is not None else '-'):>6}  "
                  f"{r['risk_level'] or ''}")
        return 0

    if getattr(args, "compare", None):
        import db_store
        a, b = args.compare
        cmp = db_store.compare(a, b, getattr(args, "db_path", None))
        print(f"Compare scan #{a} ({cmp['scan_a']['ts']}) vs #{b} ({cmp['scan_b']['ts']})")
        print(f"  Domain     : {cmp['scan_a']['domain']}")
        print(f"  Score      : {cmp['scan_a']['score']} -> {cmp['scan_b']['score']} "
              f"(delta {cmp['score_delta']:+.1f})")
        print(f"  New subs   : {', '.join(cmp['new_subdomains']) or '-'}")
        print(f"  Gone subs  : {', '.join(cmp['gone_subdomains']) or '-'}")
        print(f"  New findings:")
        for h, t in cmp["new_findings"]:
            print(f"    - [{h}] {t}")
        if not cmp["new_findings"]:
            print("    -")
        print(f"  Fixed findings:")
        for h, t in cmp["fixed_findings"]:
            print(f"    - [{h}] {t}")
        if not cmp["fixed_findings"]:
            print("    -")
        return 0

    if not args.domain:
        parser.error("the following argument is required: -d/--domain")

    # Sanity check the domain early
    try:
        from core.utils import sanitize_domain
        domain = sanitize_domain(args.domain)
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2

    # Make sure we're run from the project root so relative paths work
    project_root = os.path.dirname(os.path.abspath(__file__))
    if os.getcwd() != project_root:
        os.chdir(project_root)
    sys.path.insert(0, project_root)

    # Configure the rate limiter before anything that does network I/O
    from core.rate_limiter import configure as configure_limiter
    limiter = configure_limiter(rate=args.rate, burst=args.burst)
    logging.info("Rate limiter: %s", limiter)

    # Load the in-scope domain list (for subdomain filtering)
    from core.scope import load_scope
    scope = load_scope(args.scope, primary=domain)
    if args.scope:
        logging.info("Loaded scope: %d entries (primary=%s)", len(scope), domain)

    # Build the runner
    from core.runner import ScannerRunner
    runner = ScannerRunner(
        skip_ports=args.no_ports,
        skip_admin=args.no_admin,
        skip_mx=args.no_mx,
        skip_historical=args.no_historical,
        skip_origin=args.no_origin,
        max_subdomains=args.max_subdomains,
        rate_limiter=limiter,
        scope=scope,
        checkpoint_path=None if args.no_checkpoint else args.checkpoint,
        resume_from=args.resume,
        use_baseline=not args.no_baseline,
        syslog_target=args.syslog,
        webhook_url=args.webhook,
        telegram_token=args.tg_token,
        telegram_chat=args.tg_chat,
        map_cves=args.cves,
        cve_deep=args.cves_deep,
        active_poc=args.poc,
        critical_web=not args.no_critical_web,
        # NEW: Advanced modules (v0.19)
        enable_asm=args.asm,
        enable_cloud=args.cloud,
        enable_api_scan=args.api_scan,
        auth_config=args.auth,
        sbom_file=args.sbom,
        enable_mitre=args.mitre,
        report_type=args.report,
        integrations_config=args.integrations,
        # NEW: Red Team (v0.20)
        enable_redteam=args.redteam,
        # NEW: Metasploit service mapping (v0.22)
        enable_msf_map=getattr(args, "msf_map", False),
        # NEW: httpx + nuclei (v0.23)
        enable_httpx=getattr(args, "httpx", False),
        enable_nuclei=getattr(args, "nuclei", False),
        nuclei_severity=getattr(args, "nuclei_severity",
                                 "info,low,medium,high,critical"),
    )

    print(f"[+] Attack Surface Scanner v{__version__}")
    print(f"[+] Target: {domain}")
    print(f"[+] Flags : ports={'OFF' if args.no_ports else 'ON'}, "
          f"admin={'OFF' if args.no_admin else 'ON'}, "
          f"mx={'OFF' if args.no_mx else 'ON'}, "
          f"historical={'OFF' if args.no_historical else 'ON'}, "
          f"origin={'OFF' if args.no_origin else 'ON'}")

    t0 = time.time()
    try:
        ctx = runner.run_full_scan(domain)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        logging.exception("Fatal error during scan: %s", e)
        return 1

    elapsed = time.time() - t0
    print(f"\n[+] Scan completed in {elapsed:.1f}s")
    print_summary(ctx)

    # ---- Post-scan exports (DB store + optional PDF) ----
    try:
        import db_store

        risk_scores = getattr(ctx, "risk_scores", {}) or {}
        per_host = [
            {"score": v.get("score", 0), "level": v.get("level", "Low")}
            for v in risk_scores.values() if isinstance(v, dict)
        ]
        overall_score = (
            sum(h["score"] for h in per_host) / len(per_host) if per_host else 0.0
        )
        overall_level = (
            max((h["level"] for h in per_host),
                key=lambda lv: {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}.get(lv, 0))
            if per_host else "Low"
        )

        # findings: dict[host -> list] — values may be dicts (hashable issue); normalize to str
        raw_findings = getattr(ctx, "findings", {}) or {}
        norm_findings = {}
        for host, items in raw_findings.items():
            if isinstance(items, dict):
                norm_findings[host] = [
                    v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, default=str)
                    for v in items.values()
                ]
            elif isinstance(items, (list, tuple)):
                norm_findings[host] = [
                    i if isinstance(i, str) else json.dumps(i, ensure_ascii=False, default=str)
                    for i in items
                ]
            else:
                norm_findings[host] = [str(items)]

        results_for_store = {
            "risk": {"overall_score": round(overall_score, 1),
                     "overall_level": overall_level},
            "findings": norm_findings,
            "hosts": [
                {
                    "host": h.get("domain") if isinstance(h, dict) else h,
                    "ip": h.get("ip") if isinstance(h, dict) else (getattr(ctx, "host_ips", {}) or {}).get(h),
                    "protocol": h.get("protocol", "https") if isinstance(h, dict) else "https",
                    "ports": ((getattr(ctx, "ports", {}) or {})
                              .get(h.get("domain") if isinstance(h, dict) else h, {})
                              .get("open_ports", [])),
                    "tech": (getattr(ctx, "technologies", {}) or {})
                            .get(h.get("domain") if isinstance(h, dict) else h, []),
                }
                for h in (getattr(ctx, "alive_hosts", []) or [])
            ],
            "subdomains": getattr(ctx, "subdomains", []) or [],
            # NEW: Advanced module results (v0.19)
            "cloud_assets": getattr(ctx, "cloud_assets", {}) or {},
            "api_endpoints": getattr(ctx, "api_endpoints", []) or [],
            "api_fuzz_results": getattr(ctx, "api_fuzz_results", []) or [],
            "mitre_coverage": getattr(ctx, "mitre_coverage", {}) or {},
            "mitre_layer": getattr(ctx, "mitre_layer", {}) or {},
            "sbom_analysis": getattr(ctx, "sbom_analysis", None),
            "auth_session": "configured" if getattr(ctx, "auth_session", None) else None,
        }

        # structured sections for the dashboard tabs
        sections = {}
        try:
            sections["admin_panels"] = {
                h: panels for h, panels in (getattr(ctx, "admin_panels", {}) or {}).items()
            }
        except Exception:
            pass
        try:
            sections["wordpress"] = getattr(ctx, "wp_recon", {}) or {}
        except Exception:
            pass
        try:
            sections["sqli"] = getattr(ctx, "sqli_probe", {}) or {}
        except Exception:
            pass
        try:
            sections["cves"] = getattr(ctx, "cve_watchlist", {}) or {}
        except Exception:
            pass
        # NEW: structured nuclei + httpx output (v0.31.1). Before this,
        # only the first 20 formatted text lines reached findings and the
        # per-finding severity/template/url/CVE were thrown away, so the
        # advisor never saw a confirmed CVE and cve_exploit scored 0.
        try:
            nuc = getattr(ctx, "nuclei_findings", None)
            if nuc:
                sections["nuclei"] = nuc[:300]
        except Exception:
            pass
        try:
            httpx_rows = getattr(ctx, "http_results", None)
            if httpx_rows:
                sections["httpx"] = httpx_rows[:500]
        except Exception:
            pass
        # Coverage note: whether the target answered at all. Without it a
        # scan of an unreachable host looks exactly like a clean scan.
        try:
            reach = getattr(ctx, "reachability", None)
            if reach:
                sections["reachability"] = reach
        except Exception:
            pass
        # Continuous ASM deltas (--asm): what appeared or disappeared
        # since the previous snapshot.
        try:
            asm = getattr(ctx, "asm_changes", None)
            if asm:
                sections["asm"] = asm[:200]
        except Exception:
            pass
        try:
            sections["email_security"] = getattr(ctx, "email_security", {}) or {}
        except Exception:
            pass
        try:
            sections["takeover"] = getattr(ctx, "takeover_risks", []) or []
        except Exception:
            pass
        # Metasploit service mapping (v0.22): check-then-payload suggestions
        try:
            msf = getattr(ctx, "msf_suggestions", []) or []
            if msf:
                sections["msf_suggestions"] = msf
        except Exception:
            pass
        # Red Team actions (v0.21): map each finding to its attack tool so
        # the dashboard can offer "open terminal with command prefilled".
        try:
            import dataclasses as _dc
            rts = []
            for a in (getattr(ctx, "redteam_actions", []) or []):
                d = _dc.asdict(a) if _dc.is_dataclass(a) else dict(a)
                if isinstance(d.get("cmd"), list):
                    d["cmd"] = " ".join(str(x) for x in d["cmd"])
                rts.append(d)
            if rts:
                sections["redteam_actions"] = rts
        except Exception:
            pass
        results_for_store["sections"] = sections
        scan_id = db_store.save_scan(results_for_store, domain, __version__,
                                     db_path=getattr(args, "db_path", None))
        print(f"[+] Saved to database: scan #{scan_id}")

        # ---- Auto Red Team Pipeline (automatic after scan) ----
        try:
            from modules.redteam.auto_pipeline import build_auto_pipeline
            rt_result = build_auto_pipeline(results_for_store)
            if rt_result.get("best_targets"):
                results_for_store["redteam_pipeline"] = {
                    "best_targets": rt_result["best_targets"][:5],
                    "kill_chain": rt_result.get("kill_chain"),
                    "lateral": rt_result.get("lateral"),
                    "next_steps": rt_result.get("next_steps"),
                    "summary": rt_result.get("summary"),
                }
                db_store.save_scan(results_for_store, domain, __version__,
                                   db_path=getattr(args, "db_path", None))
                n_targets = len(rt_result["best_targets"])
                n_kc = (rt_result.get("kill_chain") or {}).get("count", 0)
                n_lat = (rt_result.get("lateral") or {}).get("total_hops", 0)
                print(f"[+] Auto Red Team: {n_targets} target(s), "
                      f"{n_kc} kill chain(s), {n_lat} lateral hop(s)")
                for step in (rt_result.get("next_steps") or [])[:3]:
                    print(f"    → {step}")
        except Exception as _rte:
            logging.warning("Auto red team pipeline failed: %s", _rte)

        if getattr(args, "pdf", False):
            from modules.pdf_report import build_pdf
            pdf_path = f"reports/output_{domain}.pdf"
            os.makedirs("reports", exist_ok=True)
            build_pdf(results_for_store, domain, pdf_path)
            print(f"[+] PDF report: {pdf_path}")

        # Nessus-grade HTML report (always — it's the primary deliverable)
        try:
            from modules.html_report import build_html_report
            html_path = f"reports/report_{domain}.html"
            os.makedirs("reports", exist_ok=True)
            cve_intel = []
            try:
                for per_host in (getattr(ctx, "cve_watchlist", {}) or {}).values():
                    for grp in per_host if isinstance(per_host, list) else []:
                        cve_intel.extend(grp.get("cves", []) if isinstance(grp, dict) else [])
            except Exception:
                cve_intel = []
            build_html_report(results_for_store, domain, html_path,
                              cve_intel=cve_intel,
                              host_ips=getattr(ctx, "host_ips", {}) or {})
            print(f"[+] HTML report: {html_path}")
        except Exception as _he:
            logging.warning("HTML report failed: %s", _he)

        # ---- Auto-Hunt / Exploit Hand-off ----
        def sqli_probe_sqlmap(candidates):
            from modules.sqli_probe import sqlmap_commands
            return sqlmap_commands(candidates)
        if getattr(args, "hunt_plan", False) or getattr(args, "auto_hunt", False):
            from modules import auto_hunt
            os.makedirs("reports", exist_ok=True)
            actions = auto_hunt.map_findings(
                results_for_store.get("findings") or {}, domain, scope
            )
            # add sqlmap candidates from sqli_probe (plan-only)
            try:
                sqli = getattr(ctx, "sqli_probe", {}) or {}
                extra = []
                for host, pr in sqli.items():
                    for cmd in sqli_probe_sqlmap(pr.get("candidates") or []):
                        extra.append(auto_hunt.HuntAction(
                            tool="sqlmap", cmd=cmd, safe=False,
                            finding=f"SQL error disclosure on {host}",
                            host=host, category="sqli"))
                actions.extend(extra)
            except Exception:
                pass
            plan_md = auto_hunt.write_hunt_plan(
                actions, domain, f"reports/hunt_{domain}.md")
            auto_hunt.write_nuclei_targets(
                results_for_store.get("subdomains") or [],
                f"reports/hunt_targets_{domain}.txt")
            auto_hunt.write_msf_rc(actions, f"reports/hunt_{domain}.rc")
            print(f"[+] Hunt plan: {plan_md} "
                  f"({sum(1 for a in actions if a.safe)} safe / "
                  f"{sum(1 for a in actions if not a.safe)} active)")
            if getattr(args, "auto_hunt", False):
                import shutil
                missing = sorted({a.tool for a in actions if a.safe
                                  and shutil.which(a.tool) is None})
                if missing:
                    print(f"[!] Skipping missing tools: {', '.join(missing)}")
                hunts = auto_hunt.run_safe(actions)
                ok = sum(1 for r in hunts if r["rc"] == 0)
                print(f"[+] Auto-hunt ran {ok}/{len(hunts)} safe actions "
                      f"(active tools remain plan-only)")
                import json as _json
                with open(f"reports/hunt_results_{domain}.json", "w") as fh:
                    _json.dump(hunts, fh, ensure_ascii=False, indent=1)
    except Exception as e:
        import traceback; logging.warning("Post-scan export failed: %s\n%s", e, traceback.format_exc())

    return 1 if ctx.errors else 0  # soft errors are reported but don't abort earlier


if __name__ == "__main__":
    sys.exit(main())
