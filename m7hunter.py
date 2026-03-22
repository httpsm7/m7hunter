#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ═══════════════════════════════════════════════════════════════════════
#   M7HUNTER v3.0 — World's #1 Bug Bounty & Pentest Pipeline
#   Made by MilkyWay Intelligence | Author: Sharlix
# ═══════════════════════════════════════════════════════════════════════

import os, sys, argparse, time, signal

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.banner   import print_banner
from core.logger   import Logger
from core.utils    import check_root
from core.config   import ConfigManager

def _sigint(sig, frame):
    print("\n\033[93m[!] Interrupted — saving state...\033[0m")
    sys.exit(0)
signal.signal(signal.SIGINT, _sigint)


def parse_args():
    p = argparse.ArgumentParser(
        prog="m7hunter",
        formatter_class=argparse.RawTextHelpFormatter,
        description="M7HUNTER v3.0 — World #1 Bug Bounty Pipeline",
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  EXAMPLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  sudo m7hunter -u example.com --deep
  sudo m7hunter -u example.com --stealth --tor
  sudo m7hunter -f targets.txt --quick --threads 100
  sudo m7hunter -u example.com --deep --cookie "session=abc123"
  sudo m7hunter -u example.com --continuous --interval 3600
  sudo m7hunter --install
  sudo m7hunter --brain
  sudo m7hunter --analyze
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    )

    # ── Input ────────────────────────────────────────────────────
    inp = p.add_mutually_exclusive_group()
    inp.add_argument("-u", metavar="URL",  dest="url",  help="Single target domain/URL/IP")
    inp.add_argument("-f", metavar="FILE", dest="file", help="File with list of targets")

    # ── Scan modes ───────────────────────────────────────────────
    modes = p.add_mutually_exclusive_group()
    modes.add_argument("--quick",      action="store_true", help="Fast scan — top tools only")
    modes.add_argument("--deep",       action="store_true", help="Full pipeline — all 21 steps")
    modes.add_argument("--stealth",    action="store_true", help="Tor + slow jitter + full pipeline")
    modes.add_argument("--custom",     action="store_true", help="Select steps manually")
    modes.add_argument("--continuous", action="store_true", help="Repeat scan on interval")

    # ── Custom steps ─────────────────────────────────────────────
    for step in ["subdomain","dns","probe","ports","crawl","nuclei","xss",
                 "sqli","cors","lfi","ssrf","redirect","takeover","screenshot",
                 "wpscan","github","cloud","ssti","jwt","graphql","host_header"]:
        p.add_argument(f"--{step}", action="store_true", help=f"[custom] run {step} step")

    # ── Auth ─────────────────────────────────────────────────────
    p.add_argument("--cookie",           metavar="STR",   help="Cookie for authenticated scanning")
    p.add_argument("--headers",          metavar="FILE",  help="Custom headers file (key: value per line)")
    p.add_argument("--auth",             metavar="U:P",   help="Basic auth user:pass")

    # ── Scope ────────────────────────────────────────────────────
    p.add_argument("--scope",            metavar="FILE",  help="In-scope domains file")
    p.add_argument("--exclude",          metavar="FILE",  help="Exclude patterns file")

    # ── General options ───────────────────────────────────────────
    p.add_argument("-o",  "--output",    metavar="DIR",   help="Output directory")
    p.add_argument("-t",  "--threads",   metavar="N",     type=int, default=50)
    p.add_argument("--tor",              action="store_true", help="Enable Tor IP rotation")
    p.add_argument("--rate",             metavar="N",     type=int, default=1000)
    p.add_argument("--timeout",          metavar="N",     type=int, default=300)
    p.add_argument("--proxy",            metavar="URL",   help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    p.add_argument("--resume",           action="store_true", help="Resume interrupted scan")
    p.add_argument("--interval",         metavar="SEC",   type=int, default=3600)
    p.add_argument("--no-color",         action="store_true")
    p.add_argument("-c", "--config",     metavar="FILE",  help="Config YAML file")

    # ── Notifications ────────────────────────────────────────────
    p.add_argument("--telegram-token",   metavar="TOKEN")
    p.add_argument("--telegram-chat",    metavar="ID")
    p.add_argument("--discord-webhook",  metavar="URL")

    # ── API keys ─────────────────────────────────────────────────
    p.add_argument("--github-token",     metavar="TOKEN")
    p.add_argument("--shodan-key",       metavar="KEY")
    p.add_argument("--vt-key",           metavar="KEY")
    p.add_argument("--wpscan-token",     metavar="TOKEN")
    p.add_argument("--interactsh-url",   metavar="URL")

    # ── Maintenance ───────────────────────────────────────────────
    p.add_argument("--install",          action="store_true", help="Install all tools")
    p.add_argument("--update",           action="store_true", help="Update all tools")
    p.add_argument("--check",            action="store_true", help="Check tool versions")
    p.add_argument("--analyze",          action="store_true", help="Analyze scans + upgrade report")
    p.add_argument("--brain",            action="store_true", help="Open M7 Brain console (admin)")
    p.add_argument("--check-tools",      action="store_true", dest="check_tools",
                   help="Full tool health check via Brain")

    return p.parse_args()


def main():
    check_root()
    print_banner()

    args = parse_args()
    log  = Logger(no_color=args.no_color)

    # Load config file
    cfg = ConfigManager(args)
    cfg.load()

    # ── Maintenance modes ────────────────────────────────────────
    if args.install:
        from core.installer import ToolInstaller
        ToolInstaller(log).install_all()
        sys.exit(0)

    if args.update:
        from core.installer import ToolInstaller
        ToolInstaller(log).update_all()
        sys.exit(0)

    if args.check:
        from core.installer import ToolInstaller
        ToolInstaller(log).check_only()
        sys.exit(0)

    if args.analyze:
        from ai.analyzer import M7Analyzer
        M7Analyzer().run()
        sys.exit(0)

    if getattr(args, 'brain', False):
        from ai.brain import M7Brain
        brain = M7Brain()
        if brain.authenticate():
            brain.interactive_mode()
        sys.exit(0)

    if getattr(args, 'check_tools', False):
        from ai.brain import M7Brain
        brain = M7Brain()
        if brain.authenticate():
            brain._check_all_tools()
        sys.exit(0)

    # ── Validate target ──────────────────────────────────────────
    if not args.url and not args.file:
        log.error("No target! Use -u <domain> or -f <file>")
        sys.exit(1)

    # Stealth auto-enables Tor
    if args.stealth:
        args.tor = True

    # ── Pre-flight ────────────────────────────────────────────────
    from core.installer import ToolInstaller
    ToolInstaller(log).check_only()

    # ── Tor setup ────────────────────────────────────────────────
    tor = None
    if args.tor:
        from core.tor_manager import TorManager
        tor = TorManager(log)
        tor.start()

    # ── OOB/Interactsh ───────────────────────────────────────────
    oob = None
    try:
        from engines.interactsh import InteractshClient
        oob = InteractshClient(
            custom_url=getattr(args, 'interactsh_url', None),
            log=log
        )
        oob.start()
    except Exception as e:
        log.warn(f"OOB init failed: {e} — blind detection disabled")

    # ── Notifications ────────────────────────────────────────────
    notifier = None
    tg_token = getattr(args, 'telegram_token', None) or cfg.get('telegram_token')
    tg_chat  = getattr(args, 'telegram_chat',  None) or cfg.get('telegram_chat')
    dc_hook  = getattr(args, 'discord_webhook',None) or cfg.get('discord_webhook')
    if tg_token and tg_chat:
        from core.notifier import Notifier
        notifier = Notifier(
            telegram_token=tg_token,
            telegram_chat=tg_chat,
            discord_webhook=dc_hook or "",
            log=log
        )

    # ── Collect targets ──────────────────────────────────────────
    targets = []
    if args.url:
        targets = [args.url.strip()]
    elif args.file:
        if not os.path.isfile(args.file):
            log.error(f"File not found: {args.file}")
            sys.exit(1)
        with open(args.file) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    # ── Scope ────────────────────────────────────────────────────
    scope_list = []
    if getattr(args, 'scope', None) and os.path.isfile(args.scope):
        with open(args.scope) as f:
            scope_list = [l.strip() for l in f if l.strip()]
        log.info(f"Scope: {len(scope_list)} entries loaded")

    log.success(f"Targets: {len(targets)}")

    # ── Run ──────────────────────────────────────────────────────
    def run_all():
        from core.pipeline import Pipeline
        all_reports = []
        for i, target in enumerate(targets, 1):
            log.section(f"TARGET {i}/{len(targets)}: {target}")
            pipeline = Pipeline(target, args, tor, oob, notifier, log, scope_list)
            report   = pipeline.run()
            if report:
                all_reports.append(report)
        return all_reports

    if getattr(args, 'continuous', False):
        log.section(f"CONTINUOUS MODE — every {args.interval}s")
        run_count = 0
        while True:
            run_count += 1
            log.info(f"Run #{run_count}")
            run_all()
            log.info(f"Next run in {args.interval}s...")
            time.sleep(args.interval)
    else:
        reports = run_all()
        log.section("ALL TARGETS COMPLETE")
        for r in reports:
            log.success(f"Report → {r}")

    # ── Cleanup ───────────────────────────────────────────────────
    if oob:
        try: oob.stop()
        except Exception: pass
    if tor:
        tor.stop()


if __name__ == "__main__":
    main()
