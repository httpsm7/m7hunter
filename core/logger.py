#!/usr/bin/env python3
import sys
from datetime import datetime

R="\033[91m"; B="\033[34m"; C="\033[96m"; Y="\033[93m"
G="\033[92m"; W="\033[97m"; DIM="\033[2m"; RST="\033[0m"; BOLD="\033[1m"

class Logger:
    def __init__(self, no_color=False):
        self.no_color = no_color
        self._step_total = 0
        self._step_current = 0
        self._findings_count = {"critical":0,"high":0,"medium":0,"low":0,"info":0}

    def _ts(self):
        return f"{DIM}[{datetime.now().strftime('%H:%M:%S')}]{RST}"

    def set_steps(self, total):
        self._step_total = total
        self._step_current = 0

    def step(self, name):
        self._step_current += 1
        bar = self._bar(self._step_current, self._step_total)
        print(f"\n{B}{'━'*70}{RST}")
        print(f"{B}  STEP [{self._step_current}/{self._step_total}]{RST} {BOLD}{W}{name}{RST}  {bar}")
        print(f"{B}{'━'*70}{RST}\n")

    def _bar(self, cur, tot):
        if not tot: return ""
        filled = int((cur/tot)*24)
        bar = f"{G}{'█'*filled}{DIM}{'░'*(24-filled)}{RST}"
        return f"[{bar}] {G}{int((cur/tot)*100)}%{RST}"

    def info(self, msg):    print(f"{self._ts()} {C}[*]{RST} {msg}")
    def success(self, msg): print(f"{self._ts()} {G}[✓]{RST} {msg}")
    def warn(self, msg):    print(f"{self._ts()} {Y}[!]{RST} {msg}")
    def error(self, msg):   print(f"{self._ts()} {R}[✗]{RST} {msg}", file=sys.stderr)

    def section(self, title):
        print(f"\n{B}{'═'*70}{RST}")
        print(f"{B}  ▶  {W}{BOLD}{title}{RST}")
        print(f"{B}{'═'*70}{RST}\n")

    def finding(self, sev, vuln_type, url, detail=""):
        col = {
            "critical": f"{R}{BOLD}",
            "high":     R,
            "medium":   Y,
            "low":      G,
            "info":     C,
        }.get(sev.lower(), W)
        self._findings_count[sev.lower()] = self._findings_count.get(sev.lower(), 0) + 1
        print(f"{self._ts()} {col}[{sev.upper():8s}]{RST} {Y}{vuln_type}{RST} → {W}{url}{RST} {DIM}{detail}{RST}")

    def live_stats(self):
        fc = self._findings_count
        print(f"\n{B}  LIVE STATS:{RST} "
              f"{R}CRIT:{fc.get('critical',0)}{RST} "
              f"{R}HIGH:{fc.get('high',0)}{RST} "
              f"{Y}MED:{fc.get('medium',0)}{RST} "
              f"{G}LOW:{fc.get('low',0)}{RST}")

    def pipeline_done(self, target, elapsed, report_path):
        fc = self._findings_count
        total = sum(fc.values())
        print(f"""
{G}{'═'*70}{RST}
{G}  ✅  PIPELINE COMPLETE — {target}{RST}
{G}  ⏱   Time      : {elapsed:.1f}s ({elapsed/60:.1f} min){RST}
{G}  🚨  Findings  : {total} total | {R}CRIT:{fc.get('critical',0)}{G} | HIGH:{fc.get('high',0)} | {Y}MED:{fc.get('medium',0)}{G} | LOW:{fc.get('low',0)}{RST}
{G}  📊  Report    : {report_path}{RST}
{G}{'═'*70}{RST}
""")
