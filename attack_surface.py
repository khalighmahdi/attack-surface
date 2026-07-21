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
import logging
import os
import sys
import time
from pathlib import Path


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
        current_version = "0.7.0"
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
        print("  Risk by host:")
        for host, info in ctx.risk_scores.items():
            if isinstance(info, dict):
                level = info.get("level", "?")
                score = info.get("score", 0)
                print(f"    - {host:40s} {level:8s} ({score})")
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


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(verbose=args.verbose)

    # --update is a special case: no domain required
    if args.update:
        return do_update()

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
    )

    print(f"[+] Attack Surface Scanner v0.7.0")
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
    return 0 if not ctx.errors else 0  # soft errors don't fail the run


if __name__ == "__main__":
    sys.exit(main())
