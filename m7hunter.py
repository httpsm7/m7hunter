#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ═══════════════════════════════════════════════════════════════════════
#   M7HUNTER v5.0 — World's #1 Bug Bounty & Pentest Pipeline
#   Dual-Phase | Confidence Scoring | Proof Engine | OSINT | Telegram Bot
#   Made by MilkyWay Intelligence | Author: Sharlix
# ═══════════════════════════════════════════════════════════════════════

import os, sys, argparse, time, signal, asyncio

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
        description="M7HUNTER v5.0 — World #1 Bug Bounty Pipeline",
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  EXAMPLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  sudo m7hunter -u example.com --deep
  sudo m7hunter -u example.com --fast
  sudo m7hunter -u example.com --stealth --tor
  sudo m7hunter -u example.com --deep --auto-exploit
  sudo m7hunter -u example.com --osint
  sudo m7hunter --dashboard
  sudo m7hunter --brain
  sudo m7hunter --telegram-bot
  sudo m7hunter --analyze
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    )

    # ── Input ─────────────────────────────────────────────────────
    inp = p.add_mutually_exclusive_group()
    inp.add_argument("-u", metavar="URL",  dest="url",  help="Single target domain/URL/IP")
    inp.add_argument("-f", metavar="FILE", dest="file", help="File with list of targets")

    # ── Scan modes ────────────────────────────────────────────────
    modes = p.add_mutually_exclusive_group()
    modes.add_argument("--fast",       action="store_true", help="Phase-1 only: fast signal detection")
    modes.add_argument("--deep",       action="store_true", help="Full pipeline: Phase-1 + Phase-2 confirmation")
    modes.add_argument("--stealth",    action="store_true", help="Deep + Tor + slow jitter")
    modes.add_argument("--custom",     action="store_true", help="Select steps manually")
    modes.add_argument("--continuous", action="store_true", help="Repeat scan on interval")

    # ── All 24 steps as custom flags ──────────────────────────────
    for step in ["subdomain","dns","probe","ports","crawl","nuclei","xss",
                 "sqli","cors","lfi","ssrf","redirect","takeover","screenshot",
                 "wpscan","github","cloud","ssti","jwt","graphql","host_header",
                 "idor","xxe","smuggling"]:
        p.add_argument(f"--{step}", action="store_true")

    # ── Auth ──────────────────────────────────────────────────────
    p.add_argument("--cookie",  metavar="STR",  help="Cookie for authenticated scanning")
    p.add_argument("--headers", metavar="FILE", help="Custom headers file")
    p.add_argument("--auth",    metavar="U:P",  help="Basic auth user:pass")

    # ── Scope ─────────────────────────────────────────────────────
    p.add_argument("--scope",   metavar="FILE", help="In-scope domains file")
    p.add_argument("--exclude", metavar="FILE", help="Exclude patterns file")

    # ── Performance ───────────────────────────────────────────────
    p.add_argument("-o","--output", metavar="DIR")
    p.add_argument("-t","--threads", metavar="N", type=int, default=50)
    p.add_argument("--rate",         metavar="N", type=int, default=1000)
    p.add_argument("--timeout",      metavar="N", type=int, default=300)
    p.add_argument("--concurrency",  metavar="N", type=int, default=10,
                   help="Async concurrency limit (default: 10)")
    p.add_argument("--proxy",        metavar="URL")
    p.add_argument("--resume",       action="store_true")
    p.add_argument("--interval",     metavar="SEC", type=int, default=3600)
    p.add_argument("--no-color",     action="store_true")

    # ── Config ────────────────────────────────────────────────────
    p.add_argument("-c","--config",  metavar="FILE")
    p.add_argument("--wordlist",     metavar="FILE")

    # ── Tor ───────────────────────────────────────────────────────
    p.add_argument("--tor",          action="store_true")

    # ── Notifications ─────────────────────────────────────────────
    p.add_argument("--telegram-token",  metavar="TOKEN")
    p.add_argument("--telegram-chat",   metavar="ID")
    p.add_argument("--discord-webhook", metavar="URL")

    # ── Telegram bot control ──────────────────────────────────────
    p.add_argument("--telegram-bot",    action="store_true",
                   help="Start Telegram bot for remote scan control")

    # ── API keys ──────────────────────────────────────────────────
    p.add_argument("--github-token",  metavar="TOKEN")
    p.add_argument("--shodan-key",    metavar="KEY")
    p.add_argument("--vt-key",        metavar="KEY")
    p.add_argument("--wpscan-token",  metavar="TOKEN")
    p.add_argument("--censys-id",     metavar="ID",  help="Censys API ID")
    p.add_argument("--censys-secret", metavar="KEY", help="Censys API Secret")
    p.add_argument("--fofa-key",      metavar="KEY", help="FOFA API key")
    p.add_argument("--interactsh-url",metavar="URL")

    # ── V5 New Features ───────────────────────────────────────────
    p.add_argument("--osint",         action="store_true",
                   help="Run OSINT module (Shodan/Censys/FOFA/crt.sh/GitHub)")
    p.add_argument("--phase1-only",   action="store_true",
                   help="Run Phase-1 fast scan only (no deep confirmation)")
    p.add_argument("--confidence",    metavar="F", type=float, default=0.8,
                   help="Min confidence for findings (0.0-1.0, default: 0.8)")
    p.add_argument("--proof",         action="store_true",
                   help="Generate proof for all confirmed findings")
    p.add_argument("--risk-score",    action="store_true",
                   help="Generate CVSS-like risk score for each finding")
    p.add_argument("--ai-model",      metavar="MODEL", default="mistral")
    p.add_argument("--auto-exploit",  action="store_true")
    p.add_argument("--exploit-threads",metavar="N", type=int, default=10)

    # ── Platform ──────────────────────────────────────────────────
    p.add_argument("--dashboard",     action="store_true")
    p.add_argument("--dashboard-port",metavar="PORT", type=int, default=8719)
    p.add_argument("--setup-vscode",  action="store_true")

    # ── Maintenance ───────────────────────────────────────────────
    p.add_argument("--install",       action="store_true")
    p.add_argument("--update",        action="store_true")
    p.add_argument("--check",         action="store_true")
    p.add_argument("--analyze",       action="store_true")
    p.add_argument("--brain",         action="store_true")
    p.add_argument("--check-tools",   action="store_true", dest="check_tools")
    p.add_argument("--open-your-brain", action="store_true", dest="open_brain",
                   help="Open encrypted brain DB viewer")
    p.add_argument("--setup-ai",      action="store_true")

    return p.parse_args()


def main():
    check_root()
    print_banner()

    args = parse_args()
    log  = Logger(no_color=args.no_color)

    cfg = ConfigManager(args)
    cfg.load()

    # ── Maintenance modes ─────────────────────────────────────────
    if args.install:
        from core.installer import ToolInstaller
        ToolInstaller(log).install_all(); sys.exit(0)

    if args.update:
        from core.installer import ToolInstaller
        ToolInstaller(log).update_all(); sys.exit(0)

    if args.check:
        from core.installer import ToolInstaller
        ToolInstaller(log).check_only(); sys.exit(0)

    if args.analyze:
        from ai.analyzer import M7Analyzer
        M7Analyzer().run(); sys.exit(0)

    if getattr(args, 'brain', False):
        from ai.brain import M7Brain
        b = M7Brain()
        if b.authenticate(): b.interactive_mode()
        sys.exit(0)

    if getattr(args, 'open_brain', False):
        from ai.brain_viewer import BrainViewer
        BrainViewer().run()
        sys.exit(0)

    if getattr(args, 'check_tools', False):
        from ai.brain import M7Brain
        b = M7Brain()
        if b.authenticate(): b._check_all_tools()
        sys.exit(0)

    if getattr(args, 'setup_vscode', False):
        from integrations.vscode import setup_vscode
        setup_vscode("."); sys.exit(0)

    if getattr(args, 'setup_ai', False):
        log.section("AI Setup — Ollama")
        from ai.offline.ollama_engine import OfflineAI as OllamaAI
        if OllamaAI.install_ollama():
            log.success("Ollama installed")
            OllamaAI.pull_model(args.ai_model)
            log.success(f"Model ready: {args.ai_model}")
        else:
            log.error("Install failed. Try: curl -fsSL https://ollama.ai/install.sh | sh")
        sys.exit(0)

    # ── Dashboard standalone mode ──────────────────────────────────
    if getattr(args, 'dashboard', False) and not args.url and not args.file:
        from web.dashboard import Dashboard
        Dashboard(log=log, port=args.dashboard_port,
                  results_dir=args.output or "results").start(blocking=True)
        sys.exit(0)

    # ── Telegram bot mode ─────────────────────────────────────────
    if getattr(args, 'telegram_bot', False):
        tg_token = getattr(args, 'telegram_token', None) or cfg.get('telegram_token')
        if not tg_token:
            log.error("--telegram-bot requires --telegram-token TOKEN")
            sys.exit(1)
        from integrations.telegram_bot import TelegramBot
        TelegramBot(token=tg_token, log=log).run()
        sys.exit(0)

    # ── Exploit standalone mode ────────────────────────────────────
    if hasattr(args, 'exploit') and getattr(args, 'exploit', None):
        log.section("Auto-Exploit Engine v5")
        from exploit.auto_exploit import AutoExploitEngine
        AutoExploitEngine(
            args.exploit,
            threads=args.exploit_threads,
            log=log
        ).run()
        sys.exit(0)

    # ── Validate target ───────────────────────────────────────────
    if not args.url and not args.file:
        log.error("No target! Use -u <domain> or -f <file>")
        sys.exit(1)

    # Stealth auto-enables Tor
    if args.stealth:
        args.tor = True

    # ── Pre-flight check ──────────────────────────────────────────
    from core.installer import ToolInstaller
    ToolInstaller(log).check_only()

    # ── Start dashboard in background if requested ─────────────────
    if getattr(args, 'dashboard', False):
        from web.dashboard import Dashboard
        Dashboard(log=log, port=args.dashboard_port,
                  results_dir=args.output or "results").start_background()

    # ── Tor setup ─────────────────────────────────────────────────
    tor = None
    if args.tor:
        from core.tor_manager import TorManager
        tor = TorManager(log)
        tor.start()

    # ── OOB/Interactsh ────────────────────────────────────────────
    oob = None
    try:
        from engines.interactsh import InteractshClient
        oob = InteractshClient(
            custom_url=getattr(args, 'interactsh_url', None),
            log=log
        )
        oob.start()
    except Exception as e:
        log.warn(f"OOB init failed: {e}")

    # ── AI engines ────────────────────────────────────────────────
    offline_ai = None
    ollama_ai  = None
    try:
        from ai.offline_ai import OfflineAI
        offline_ai = OfflineAI(log=log)
        log.success(f"Offline AI ready — {offline_ai.get_status()}")
    except Exception as e:
        log.warn(f"Offline AI init failed: {e}")

    try:
        from ai.offline.ollama_engine import OfflineAI as OllamaAI
        ollama_ai = OllamaAI(model=getattr(args, 'ai_model', 'mistral'), log=log)
        if ollama_ai.is_available():
            log.success(f"Ollama AI ready: {ollama_ai.model}")
        else:
            ollama_ai = None
    except Exception:
        pass

    # ── Notifier ─────────────────────────────────────────────────
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

    # ── Targets ───────────────────────────────────────────────────
    targets = []
    if args.url:
        targets = [args.url.strip()]
    elif args.file:
        if not os.path.isfile(args.file):
            log.error(f"File not found: {args.file}")
            sys.exit(1)
        with open(args.file) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    scope_list = []
    if getattr(args, 'scope', None) and os.path.isfile(args.scope):
        with open(args.scope) as f:
            scope_list = [l.strip() for l in f if l.strip()]
        log.info(f"Scope: {len(scope_list)} entries")

    log.success(f"Targets: {len(targets)}")

    # ── Run pipeline ──────────────────────────────────────────────
    def run_all():
        from core.pipeline_v5 import PipelineV5
        reports = []
        for i, target in enumerate(targets, 1):
            log.section(f"TARGET {i}/{len(targets)}: {target}")
            pipeline = PipelineV5(
                target=target,
                args=args,
                tor=tor,
                oob=oob,
                notifier=notifier,
                log=log,
                scope_list=scope_list,
                offline_ai=offline_ai,
                ollama_ai=ollama_ai,
                confidence_threshold=getattr(args, 'confidence', 0.8),
            )
            report = pipeline.run()
            if report:
                reports.append(report)
                # Auto-exploit if requested
                if getattr(args, 'auto_exploit', False):
                    log.section("AUTO-EXPLOIT ENGINE v5")
                    from exploit.auto_exploit import AutoExploitEngine
                    AutoExploitEngine(
                        pipeline.out,
                        oob_url=oob.get_payload("ssrf", "") if oob else "",
                        threads=args.exploit_threads,
                        offline_ai=offline_ai,
                        log=log
                    ).run()
        return reports

    if getattr(args, 'continuous', False):
        log.section(f"CONTINUOUS MODE — every {args.interval}s")
        n = 0
        while True:
            n += 1
            log.info(f"Run #{n}")
            run_all()
            log.info(f"Next run in {args.interval}s...")
            time.sleep(args.interval)
    else:
        reports = run_all()
        log.section("ALL TARGETS COMPLETE")
        for r in reports:
            log.success(f"Report → {r}")
        if getattr(args, 'dashboard', False):
            log.success(f"Dashboard → http://localhost:{args.dashboard_port}")

    # ── Cleanup ───────────────────────────────────────────────────
    if oob:
        try: oob.stop()
        except Exception: pass
    if tor:
        tor.stop()


if __name__ == "__main__":
    main()
