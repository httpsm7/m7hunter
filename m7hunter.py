#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ═══════════════════════════════════════════════════════════════════
#   M7HUNTER v7.0 — Bug Bounty Automation Framework
#
#   ⚠️  AUTHORIZED USE ONLY — READ LICENSE BEFORE USE
#   ✔  Authorized bug bounty programs (within scope)
#   ✔  Penetration testing with explicit written permission
#   ✔  Lab / private environments you own
#   ✔  Company invite-based security assessments
#   ❌  Unauthorized scanning is ILLEGAL
#
#   MilkyWay Intelligence | Author: Sharlix
# ═══════════════════════════════════════════════════════════════════

import os, sys, argparse, time, signal

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.banner  import print_banner
from core.logger  import Logger
from core.utils   import check_root

def _sigint(sig, frame):
    print("\n\033[93m[!] Interrupted — saving state...\033[0m")
    sys.exit(0)
signal.signal(signal.SIGINT, _sigint)


def parse_args():
    p = argparse.ArgumentParser(
        prog="m7hunter",
        description="M7HUNTER v7.0 — Bug Bounty Automation Framework (Authorized Use Only)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
━━━ EXAMPLES ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  sudo m7hunter -u target.com --deep
  sudo m7hunter -u target.com --deep --cookie "session=abc123"
  sudo m7hunter -u target.com --deep --userA "s_a=x" --userB "s_b=y"
  sudo m7hunter -u target.com --fast --confidence 0.7
  sudo m7hunter -u target.com --deep --no-double-verify
  sudo m7hunter --dashboard
  sudo m7hunter --check
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    )

    inp = p.add_mutually_exclusive_group()
    inp.add_argument("-u", metavar="URL",  dest="url")
    inp.add_argument("-f", metavar="FILE", dest="file")

    modes = p.add_mutually_exclusive_group()
    modes.add_argument("--fast",        action="store_true")
    modes.add_argument("--deep",        action="store_true")
    modes.add_argument("--stealth",     action="store_true")
    modes.add_argument("--custom",      action="store_true")
    modes.add_argument("--continuous",  action="store_true")

    # All steps
    for step in ["subdomain","dns","probe","ports","crawl","nuclei","xss","sqli","cors",
                 "lfi","ssrf","redirect","takeover","screenshot","wpscan","github","cloud",
                 "ssti","jwt","graphql","host_header","idor","xxe","smuggling","csrf","race",
                 "nosql","ws","proto_pollution"]:
        p.add_argument(f"--{step.replace('_','-')}", action="store_true", dest=step)

    # Auth
    p.add_argument("--cookie",          metavar="STR",   help="Auth cookie")
    p.add_argument("--userA",           metavar="COOKIE",help="Attacker session (IDOR)")
    p.add_argument("--userB",           metavar="COOKIE",help="Victim session (IDOR)")
    p.add_argument("--authorization",   metavar="TOKEN")
    p.add_argument("--headers",         metavar="FILE")
    p.add_argument("--cookie-b",        metavar="COOKIE", dest="cookie_b")

    # Scope
    p.add_argument("--scope",  metavar="FILE")
    p.add_argument("--exclude",metavar="FILE")

    # Performance
    p.add_argument("-o","--output",  metavar="DIR")
    p.add_argument("-t","--threads", metavar="N",  type=int, default=50)
    p.add_argument("--rate",         metavar="N",  type=int, default=1000)
    p.add_argument("--proxy",        metavar="URL")
    p.add_argument("--resume",       action="store_true")
    p.add_argument("--no-color",     action="store_true")
    p.add_argument("--interval",     metavar="SEC", type=int, default=3600)

    # V7 features
    p.add_argument("--confidence",      metavar="F",   type=float, default=0.8)
    p.add_argument("--no-double-verify",action="store_true", dest="no_double_verify")
    p.add_argument("--no-http2",        action="store_true", dest="no_http2")
    p.add_argument("--phase1-only",     action="store_true", dest="phase1_only")

    # Config
    p.add_argument("-c","--config",  metavar="FILE")
    p.add_argument("--wordlist",     metavar="FILE")
    p.add_argument("--tor",          action="store_true")

    # Notifications
    p.add_argument("--telegram-token",  metavar="TOKEN", dest="telegram_token")
    p.add_argument("--telegram-chat",   metavar="ID",    dest="telegram_chat")
    p.add_argument("--discord-webhook", metavar="URL",   dest="discord_webhook")
    p.add_argument("--telegram-bot",    action="store_true", dest="telegram_bot")

    # API keys
    p.add_argument("--github-token",  metavar="TOKEN", dest="github_token")
    p.add_argument("--shodan-key",    metavar="KEY",   dest="shodan_key")
    p.add_argument("--vt-key",        metavar="KEY",   dest="vt_key")
    p.add_argument("--wpscan-token",  metavar="TOKEN", dest="wpscan_token")
    p.add_argument("--interactsh-url",metavar="URL",   dest="interactsh_url")

    # Platform
    p.add_argument("--dashboard",      action="store_true")
    p.add_argument("--dashboard-port", metavar="PORT", type=int, default=8719)
    p.add_argument("--osint",          action="store_true")

    # Maintenance
    p.add_argument("--install",        action="store_true")
    p.add_argument("--update",         action="store_true")
    p.add_argument("--check",          action="store_true")
    p.add_argument("--analyze",        action="store_true")
    p.add_argument("--brain",          action="store_true")
    p.add_argument("--open-your-brain",action="store_true", dest="open_brain")
    p.add_argument("--setup-brain",    action="store_true", dest="setup_brain")
    p.add_argument("--setup-ai",       action="store_true", dest="setup_ai")

    return p.parse_args()


def main():
    check_root()
    print_banner()
    args = parse_args()
    log  = Logger(no_color=args.no_color)

    # ── Maintenance ───────────────────────────────────────────────────
    if args.install:
        from core.installer import ToolInstaller
        ToolInstaller(log).install_all(); sys.exit(0)

    if args.update:
        from core.installer import ToolInstaller
        ToolInstaller(log).update_all(); sys.exit(0)

    if args.check:
        from core.installer import ToolInstaller
        ToolInstaller(log).check_only(); sys.exit(0)

    if getattr(args,'brain',False):
        from ai.secure_db import SecureDB
        db = SecureDB()
        if db.authenticate():
            log.success("Brain authenticated")
        sys.exit(0)

    if getattr(args,'setup_brain',False):
        from ai.secure_db import SecureDB
        SecureDB()._setup_first_run(); sys.exit(0)

    if getattr(args,'dashboard',False) and not args.url and not args.file:
        try:
            from web.dashboard import Dashboard
            Dashboard(log=log, port=args.dashboard_port,
                      results_dir=args.output or "results").start(blocking=True)
        except ImportError:
            log.warn("Dashboard not available in this build"); sys.exit(1)
        sys.exit(0)

    if getattr(args,'telegram_bot',False):
        tg_token = getattr(args,'telegram_token',None)
        if not tg_token:
            log.error("--telegram-bot requires --telegram-token"); sys.exit(1)
        try:
            from integrations.telegram_bot import TelegramBot
            TelegramBot(token=tg_token, log=log).run()
        except ImportError:
            log.error("Telegram bot not available"); sys.exit(1)
        sys.exit(0)

    if not args.url and not args.file:
        log.error("No target! Use -u <domain> or -f <file>"); sys.exit(1)

    # ── Setup ─────────────────────────────────────────────────────────
    if args.stealth: args.tor = True

    # Multi-session
    if getattr(args,'userA',None) and getattr(args,'userB',None):
        args.cookie   = args.userA
        args.cookie_b = args.userB
        log.success("Multi-session IDOR mode: userA + userB")
    elif getattr(args,'userA',None):
        args.cookie = args.userA

    # Auth warning
    if not getattr(args,'cookie',None) and not getattr(args,'authorization',None):
        log.warn("No --cookie — authenticated endpoints WON'T be tested")
        log.warn("Add: --cookie 'session=your_value' for full scan")

    # CEO rules
    ceo_rules = {}
    if getattr(args,'no_double_verify',False):
        ceo_rules["double_verify"] = False
        log.info("Double-verify disabled")
    if getattr(args,'stealth',False):
        ceo_rules["stealth_min_delay_ms"] = 5000

    # Pre-flight
    from core.installer import ToolInstaller
    ToolInstaller(log).check_only()

    # Tor
    tor = None
    if args.tor:
        from core.tor_manager import TorManager
        tor = TorManager(log); tor.start()

    # OOB
    oob = None
    try:
        from engines.interactsh import InteractshClient
        oob = InteractshClient(custom_url=getattr(args,'interactsh_url',None), log=log)
        oob.start()
    except Exception: pass

    # Offline AI
    offline_ai = None
    try:
        from ai.offline_ai import OfflineAI
        offline_ai = OfflineAI(log=log)
        log.success(f"AI: {offline_ai.get_status()}")
    except Exception: pass

    # Notifier
    notifier = None
    tg_token = getattr(args,'telegram_token',None)
    tg_chat  = getattr(args,'telegram_chat',None)
    if tg_token and tg_chat:
        try:
            from core.notifier import Notifier
            notifier = Notifier(telegram_token=tg_token, telegram_chat=tg_chat, log=log)
        except Exception: pass

    # Targets
    targets = []
    if args.url:
        targets = [args.url.strip()]
    elif args.file:
        if not os.path.isfile(args.file):
            log.error(f"File not found: {args.file}"); sys.exit(1)
        with open(args.file) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    scope_list = []
    if getattr(args,'scope',None) and os.path.isfile(args.scope):
        with open(args.scope) as f:
            scope_list = [l.strip() for l in f if l.strip()]
        log.info(f"Scope: {len(scope_list)} entries loaded")

    log.success(f"Targets: {len(targets)}")

    # ── Run ───────────────────────────────────────────────────────────
    def run_all():
        from core.pipeline_v7 import PipelineV7
        reports = []
        for i, target in enumerate(targets, 1):
            log.section(f"TARGET {i}/{len(targets)}: {target}")
            pipeline = PipelineV7(
                target               = target,
                args                 = args,
                tor                  = tor,
                oob                  = oob,
                notifier             = notifier,
                log                  = log,
                scope_list           = scope_list,
                offline_ai           = offline_ai,
                confidence_threshold = getattr(args,'confidence', 0.8),
                ceo_rules            = ceo_rules,
            )
            report = pipeline.run()
            if report: reports.append(report)
        return reports

    if getattr(args,'continuous',False):
        log.section(f"CONTINUOUS MODE — every {args.interval}s")
        n = 0
        while True:
            n += 1; log.info(f"Run #{n}")
            run_all()
            log.info(f"Next in {args.interval}s...")
            time.sleep(args.interval)
    else:
        reports = run_all()
        log.section("ALL TARGETS COMPLETE")
        for r in reports:
            log.success(f"Report → {r}")

    if oob:
        try: oob.stop()
        except Exception: pass
    if tor: tor.stop()


if __name__ == "__main__":
    main()
