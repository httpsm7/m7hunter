#!/usr/bin/env python3
# core/logger.py

import sys
from datetime import datetime

R   = "\033[91m"
B   = "\033[34m"
C   = "\033[96m"
Y   = "\033[93m"
G   = "\033[92m"
W   = "\033[97m"
DIM = "\033[2m"
RST = "\033[0m"
BOLD= "\033[1m"

class Logger:
    def __init__(self, no_color=False):
        self.no_color = no_color
        self._step_total = 0
        self._step_current = 0

    def _ts(self):
        return f"{DIM}[{datetime.now().strftime('%H:%M:%S')}]{RST}"

    def set_steps(self, total):
        self._step_total = total
        self._step_current = 0

    def step(self, name):
        self._step_current += 1
        bar = self._progress_bar(self._step_current, self._step_total)
        print(f"\n{B}{'━'*62}{RST}")
        print(f"{B}  STEP [{self._step_current}/{self._step_total}]{RST} {BOLD}{W}{name}{RST}  {bar}")
        print(f"{B}{'━'*62}{RST}\n")

    def _progress_bar(self, current, total):
        if total == 0:
            return ""
        filled = int((current / total) * 20)
        bar    = f"{G}{'█' * filled}{DIM}{'░' * (20 - filled)}{RST}"
        pct    = int((current / total) * 100)
        return f"[{bar}] {G}{pct}%{RST}"

    def info(self, msg):
        print(f"{self._ts()} {C}[*]{RST} {msg}")

    def success(self, msg):
        print(f"{self._ts()} {G}[✓]{RST} {msg}")

    def warn(self, msg):
        print(f"{self._ts()} {Y}[!]{RST} {msg}")

    def error(self, msg):
        print(f"{self._ts()} {R}[✗]{RST} {msg}", file=sys.stderr)

    def section(self, title):
        print(f"\n{B}{'═'*62}{RST}")
        print(f"{B}  ▶  {W}{BOLD}{title}{RST}")
        print(f"{B}{'═'*62}{RST}\n")

    def finding(self, sev, vuln_type, url, detail=""):
        colors = {"critical": R, "high": R, "medium": Y, "low": G, "info": C}
        col = colors.get(sev.lower(), W)
        print(f"{self._ts()} {col}[{sev.upper()}]{RST} {Y}{vuln_type}{RST} → {W}{url}{RST} {DIM}{detail}{RST}")

    def pipeline_done(self, target, elapsed, report_path):
        print(f"""
{G}{'═'*62}{RST}
{G}  ✅  PIPELINE COMPLETE — {target}{RST}
{G}  ⏱   Time     : {elapsed:.1f}s ({elapsed/60:.1f} min){RST}
{G}  📊  Report   : {report_path}{RST}
{G}{'═'*62}{RST}
""")
