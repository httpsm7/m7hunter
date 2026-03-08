#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ═══════════════════════════════════════════════════════════════════════
#   M7HUNTER v2.0 — Bug Bounty & Pentest Pipeline Framework
#   Made by MilkyWay Intelligence | Author: Sharlix
# ═══════════════════════════════════════════════════════════════════════

import os
import sys
import argparse
import time

# ── Ensure project root is in path ───────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.banner   import print_banner
from core.logger   import Logger
from core.utils    import check_root, get_prefix
from core.pipeline import Pipeline

def parse_args():
    parser = argparse.ArgumentParser(
        prog="m7hunter",
        formatter_class=argparse.RawTextHelpFormatter,
        description="M7HUNTER v2.0 — Automated Bug Bounty Pipeline",
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  EXAMPLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Single URL:
    sudo python3 m7hunter.py -u example.com --deep

  File with domains:
    sudo python3 m7hunter.py -f targets.txt --quick

  Stealth mode (Tor + slow):
    sudo python3 m7hunter.py -u example.com --stealth

  Install all tools:
    sudo python3 m7hunter.py --install
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    )

    # ── Input ──────────────────────────────────────────────────────────
    inp = parser.add_mutually_exclusive_group()
    inp.add_argument("-u", metavar="URL",  dest="url",  help="Single target domain/URL/IP")
    inp.add_argument("-f", metavar="FILE", dest="file", help="File with list of targets")

    # ── Scan modes ─────────────────────────────────────────────────────
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--quick",   action="store_true", help="Fast scan — top tools only")
    modes.add_argument("--deep",    action="store_true", help="Deep scan — all modules")
    modes.add_argument("--stealth", action="store_true", help="Stealth — Tor + slow jitter + all modules")
    modes.add_argument("--custom",  action="store_true", help="Custom — select steps manually")

    # ── Pipeline step overrides (for --custom) ─────────────────────────
    parser.add_argument("--subdomain",  action="store_true", help="[custom] Subdomain enumeration")
    parser.add_argument("--dns",        action="store_true", help="[custom] DNS resolution")
    parser.add_argument("--probe",      action="store_true", help="[custom] HTTP probe")
    parser.add_argument("--ports",      action="store_true", help="[custom] Port scan")
    parser.add_argument("--crawl",      action="store_true", help="[custom] Web crawl + JS mining")
    parser.add_argument("--nuclei",     action="store_true", help="[custom] Nuclei scan")
    parser.add_argument("--xss",        action="store_true", help="[custom] XSS scan")
    parser.add_argument("--sqli",       action="store_true", help="[custom] SQLi scan")
    parser.add_argument("--cors",       action="store_true", help="[custom] CORS scan")
    parser.add_argument("--lfi",        action="store_true", help="[custom] LFI scan")
    parser.add_argument("--ssrf",       action="store_true", help="[custom] SSRF scan")
    parser.add_argument("--redirect",   action="store_true", help="[custom] Open redirect")
    parser.add_argument("--takeover",   action="store_true", help="[custom] Subdomain takeover")
    parser.add_argument("--screenshot", action="store_true", help="[custom] Screenshots")
    parser.add_argument("--wpscan",     action="store_true", help="[custom] WPScan")

    # ── Options ────────────────────────────────────────────────────────
    parser.add_argument("-o",  "--output",   metavar="DIR",   help="Output directory")
    parser.add_argument("-t",  "--threads",  metavar="N",     type=int, default=50)
    parser.add_argument("--tor",             action="store_true", help="Enable Tor IP rotation")
    parser.add_argument("--rate",            metavar="N",     type=int, default=1000)
    parser.add_argument("--wordlist",        metavar="FILE",  help="Custom subdomain wordlist")
    parser.add_argument("--proxy",           metavar="URL",   help="Proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--resume",          action="store_true", help="Resume interrupted scan")
    parser.add_argument("--install",         action="store_true", help="Install / verify all tools")
    parser.add_argument("--no-color",        action="store_true", help="Disable colors")

    # API keys
    parser.add_argument("--github-token",  metavar="TOKEN")
    parser.add_argument("--vt-key",        metavar="KEY")
    parser.add_argument("--shodan-key",    metavar="KEY")
    parser.add_argument("--wpscan-token",  metavar="TOKEN")

    return parser.parse_args()


def main():
    check_root()
    print_banner()

    args = parse_args()
    log  = Logger(no_color=args.no_color)

    # ── Install mode ──────────────────────────────────────────────────
    if args.install:
        from core.installer import ToolInstaller
        ToolInstaller(log).install_all()
        sys.exit(0)

    # ── Validate input ────────────────────────────────────────────────
    if not args.url and not args.file:
        log.error("No target specified! Use -u <domain> or -f <file>")
        sys.exit(1)

    # ── Stealth mode auto-enables Tor ─────────────────────────────────
    if args.stealth:
        args.tor = True

    # ── Pre-flight tool check ─────────────────────────────────────────
    from core.installer import ToolInstaller
    ToolInstaller(log).check_only()

    # ── Tor setup ─────────────────────────────────────────────────────
    tor = None
    if args.tor:
        from core.tor_manager import TorManager
        tor = TorManager(log, rotate_every=25)
        tor.start()

    # ── Collect targets ───────────────────────────────────────────────
    targets = []
    if args.url:
        targets = [args.url.strip()]
    elif args.file:
        if not os.path.isfile(args.file):
            log.error(f"File not found: {args.file}")
            sys.exit(1)
        with open(args.file) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    log.success(f"Loaded {len(targets)} target(s)")

    # ── Run pipeline for each target ──────────────────────────────────
    all_reports = []
    for i, target in enumerate(targets, 1):
        log.section(f"TARGET {i}/{len(targets)}: {target}")
        pipeline = Pipeline(target, args, tor, log)
        report_path = pipeline.run()
        if report_path:
            all_reports.append(report_path)

    # ── Final summary ─────────────────────────────────────────────────
    print()
    log.section("ALL TARGETS COMPLETE")
    for r in all_reports:
        log.success(f"Report → {r}")

    if tor:
        tor.stop()


if __name__ == "__main__":
    main()
