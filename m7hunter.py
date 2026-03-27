#!/usr/bin/env python3
import os, sys, argparse, time, signal
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.banner import print_banner
from core.logger import Logger
from core.utils  import check_root
from core.config import ConfigManager

def _sigint(sig,frame):
    print("\n\033[93m[!] Interrupted\033[0m"); sys.exit(0)
signal.signal(signal.SIGINT,_sigint)

def parse_args():
    p=argparse.ArgumentParser(prog="m7hunter",
      formatter_class=argparse.RawTextHelpFormatter,
      description="M7HUNTER v3.0 — World #1 Bug Bounty Pipeline")
    inp=p.add_mutually_exclusive_group()
    inp.add_argument("-u",metavar="URL",dest="url")
    inp.add_argument("-f",metavar="FILE",dest="file")
    modes=p.add_mutually_exclusive_group()
    modes.add_argument("--quick",action="store_true")
    modes.add_argument("--deep",action="store_true")
    modes.add_argument("--stealth",action="store_true")
    modes.add_argument("--custom",action="store_true")
    modes.add_argument("--continuous",action="store_true")
    for step in ["subdomain","dns","probe","ports","crawl","nuclei","xss",
                 "sqli","cors","lfi","ssrf","redirect","takeover","screenshot",
                 "wpscan","github","cloud","ssti","jwt","graphql","host_header",
                 "idor","xxe","smuggling"]:
        p.add_argument(f"--{step}",action="store_true")
    p.add_argument("--cookie",metavar="STR")
    p.add_argument("--headers",metavar="FILE")
    p.add_argument("--auth",metavar="U:P")
    p.add_argument("--scope",metavar="FILE")
    p.add_argument("--exclude",metavar="FILE")
    p.add_argument("-o","--output",metavar="DIR")
    p.add_argument("-t","--threads",metavar="N",type=int,default=50)
    p.add_argument("--tor",action="store_true")
    p.add_argument("--rate",metavar="N",type=int,default=1000)
    p.add_argument("--timeout",metavar="N",type=int,default=300)
    p.add_argument("--proxy",metavar="URL")
    p.add_argument("--resume",action="store_true")
    p.add_argument("--interval",metavar="SEC",type=int,default=3600)
    p.add_argument("--no-color",action="store_true")
    p.add_argument("-c","--config",metavar="FILE")
    p.add_argument("--telegram-token",metavar="TOKEN")
    p.add_argument("--telegram-chat",metavar="ID")
    p.add_argument("--discord-webhook",metavar="URL")
    p.add_argument("--github-token",metavar="TOKEN")
    p.add_argument("--shodan-key",metavar="KEY")
    p.add_argument("--vt-key",metavar="KEY")
    p.add_argument("--wpscan-token",metavar="TOKEN")
    p.add_argument("--interactsh-url",metavar="URL")
    p.add_argument("--ai-model",metavar="MODEL",default="mistral")
    p.add_argument("--dashboard",action="store_true")
    p.add_argument("--dashboard-port",metavar="PORT",type=int,default=8719)
    p.add_argument("--setup-vscode",action="store_true")
    p.add_argument("--setup-ai",action="store_true")
    p.add_argument("--exploit",metavar="DIR")
    p.add_argument("--auto-exploit",action="store_true")
    p.add_argument("--exploit-threads",metavar="N",type=int,default=10)
    p.add_argument("--install",action="store_true")
    p.add_argument("--update",action="store_true")
    p.add_argument("--check",action="store_true")
    p.add_argument("--analyze",action="store_true")
    p.add_argument("--brain",action="store_true")
    p.add_argument("--check-tools",action="store_true",dest="check_tools")
    p.add_argument("--wordlist",metavar="FILE")
    return p.parse_args()

def main():
    check_root(); print_banner()
    args=parse_args(); log=Logger(no_color=args.no_color)
    cfg=ConfigManager(args); cfg.load()

    if getattr(args,'setup_vscode',False):
        from integrations.vscode import setup_vscode; setup_vscode("."); sys.exit(0)

    if getattr(args,'setup_ai',False):
        log.section("AI Setup")
        from ai.offline.ollama_engine import OfflineAI
        if OfflineAI.install_ollama():
            log.success("Ollama installed")
            OfflineAI.pull_model(args.ai_model)
            log.success(f"Model ready: {args.ai_model}")
        else: log.error("Install failed. Try: curl -fsSL https://ollama.ai/install.sh | sh")
        sys.exit(0)

    if getattr(args,'dashboard',False) and not args.url and not args.file:
        from web.dashboard import Dashboard
        Dashboard(log=log,port=args.dashboard_port,
                  results_dir=args.output or "results").start(blocking=True)
        sys.exit(0)

    if getattr(args,'exploit',False):
        log.section("Auto-Exploit Engine")
        from exploit.auto_exploit import AutoExploitEngine
        from ai.offline.ollama_engine import OfflineAI
        AutoExploitEngine(args.exploit,threads=args.exploit_threads,
                          ai_engine=OfflineAI(model=args.ai_model,log=log),log=log).run()
        sys.exit(0)

    if args.install:
        from core.installer import ToolInstaller; ToolInstaller(log).install_all(); sys.exit(0)
    if args.update:
        from core.installer import ToolInstaller; ToolInstaller(log).update_all(); sys.exit(0)
    if args.check:
        from core.installer import ToolInstaller; ToolInstaller(log).check_only(); sys.exit(0)
    if args.analyze:
        from ai.analyzer import M7Analyzer; M7Analyzer().run(); sys.exit(0)
    if getattr(args,'brain',False):
        from ai.brain import M7Brain; b=M7Brain()
        if b.authenticate(): b.interactive_mode(); sys.exit(0)
    if getattr(args,'check_tools',False):
        from ai.brain import M7Brain; b=M7Brain()
        if b.authenticate(): b._check_all_tools(); sys.exit(0)

    if not args.url and not args.file:
        log.error("No target! Use -u <domain> or -f <file>"); sys.exit(1)

    if args.stealth: args.tor=True
    from core.installer import ToolInstaller; ToolInstaller(log).check_only()

    if getattr(args,'dashboard',False):
        from web.dashboard import Dashboard
        Dashboard(log=log,port=args.dashboard_port,
                  results_dir=args.output or "results").start_background()

    tor=None
    if args.tor:
        from core.tor_manager import TorManager; tor=TorManager(log); tor.start()

    oob=None
    try:
        from engines.interactsh import InteractshClient
        oob=InteractshClient(custom_url=getattr(args,'interactsh_url',None),log=log); oob.start()
    except Exception as e: log.warn(f"OOB failed: {e}")

    ai_engine=None
    try:
        from ai.offline.ollama_engine import OfflineAI
        ai_engine=OfflineAI(model=getattr(args,'ai_model','mistral'),log=log)
        if ai_engine.is_available(): log.success(f"Offline AI: {ai_engine.model}")
        else: ai_engine=None
    except Exception: pass

    notifier=None
    tg_token=getattr(args,'telegram_token',None) or cfg.get('telegram_token')
    tg_chat=getattr(args,'telegram_chat',None) or cfg.get('telegram_chat')
    if tg_token and tg_chat:
        from core.notifier import Notifier
        notifier=Notifier(tg_token,tg_chat,getattr(args,'discord_webhook',None) or "",log)

    targets=[]
    if args.url: targets=[args.url.strip()]
    elif args.file:
        if not os.path.isfile(args.file): log.error(f"File not found: {args.file}"); sys.exit(1)
        with open(args.file) as f: targets=[l.strip() for l in f if l.strip() and not l.startswith("#")]

    scope_list=[]
    if getattr(args,'scope',None) and os.path.isfile(args.scope):
        with open(args.scope) as f: scope_list=[l.strip() for l in f if l.strip()]
        log.info(f"Scope: {len(scope_list)} entries")

    log.success(f"Targets: {len(targets)}")

    def run_all():
        from core.pipeline import Pipeline
        reports=[]
        for i,target in enumerate(targets,1):
            log.section(f"TARGET {i}/{len(targets)}: {target}")
            pl=Pipeline(target,args,tor,oob,notifier,log,scope_list)
            pl.ai=ai_engine
            report=pl.run()
            if report:
                reports.append(report)
                if getattr(args,'auto_exploit',False):
                    log.section("AUTO-EXPLOIT")
                    from exploit.auto_exploit import AutoExploitEngine
                    AutoExploitEngine(pl.out,
                        oob_url=oob.get_payload("ssrf","") if oob else "",
                        threads=args.exploit_threads,ai_engine=ai_engine,log=log).run()
        return reports

    if getattr(args,'continuous',False):
        log.section(f"CONTINUOUS — every {args.interval}s")
        n=0
        while True:
            n+=1; log.info(f"Run #{n}"); run_all()
            log.info(f"Next in {args.interval}s..."); time.sleep(args.interval)
    else:
        reports=run_all(); log.section("DONE")
        for r in reports: log.success(f"Report → {r}")
        if getattr(args,'dashboard',False):
            log.success(f"Dashboard → http://localhost:{args.dashboard_port}")

    if oob:
        try: oob.stop()
        except: pass
    if tor: tor.stop()

if __name__=="__main__": main()
