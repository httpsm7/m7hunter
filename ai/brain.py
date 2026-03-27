#!/usr/bin/env python3
# ai/brain.py — M7 Brain (Tool ka CEO)
# Sab kuch yahan se control hota hai
# Encrypted DB + Pattern Engine + Command Fixer + Pipeline Controller
#
# Usage:
#   from ai.brain import M7Brain
#   brain = M7Brain()
#   if brain.authenticate():
#       brain.analyze()
#       brain.interactive_mode()
#
# MilkyWay Intelligence | Author: Sharlix

import os
import sys
import json
import time
from datetime import datetime

from ai.secure_db          import SecureDB, AccessDenied
from ai.pattern_engine     import PatternEngine
from ai.tool_knowledge     import ToolCommandEngine, TOOL_KB
from ai.analyzer           import M7Analyzer

R="\033[91m"; B="\033[34m"; C="\033[96m"; Y="\033[93m"
G="\033[92m"; W="\033[97m"; DIM="\033[2m"; RST="\033[0m"; BOLD="\033[1m"

SESSIONS_DIR = os.path.expanduser("~/.m7hunter/sessions/")


class M7Brain:
    """
    M7Hunter ka CEO — sab kuch isi ke andar hai.

    Features:
    - Encrypted DB (admin-only)
    - Pattern learning (tool behavior memory)
    - Command knowledge base (auto-fix)
    - Pipeline intelligence (miss prevention)
    - Interactive brain console
    """

    def __init__(self):
        self.db          = SecureDB()
        self.patterns    = PatternEngine()
        self.cmd_engine  = ToolCommandEngine()
        self._authenticated = False

    # ── Authentication ─────────────────────────────────────────────

    def authenticate(self, username: str = None, password: str = None) -> bool:
        """Admin credentials verify karo."""
        self._print_lock_screen()
        result = self.db.authenticate(username, password)
        if result:
            self._authenticated = True
            print(f"\n{G}[BRAIN] Access granted. Welcome, admin.{RST}\n")
        return result

    def _print_lock_screen(self):
        print(f"""
{B}  ╔══════════════════════════════════════════════╗{RST}
{B}  ║{RST}  {W}{BOLD}M7 Brain — Intelligence Core{RST}               {B}║{RST}
{B}  ║{RST}  {DIM}Admin access required{RST}                       {B}║{RST}
{B}  ║{RST}  {R}🔒 Encrypted database{RST}                       {B}║{RST}
{B}  ╚══════════════════════════════════════════════╝{RST}
""")

    def _require_auth(self):
        if not self._authenticated:
            raise AccessDenied("Brain requires authentication. Call authenticate() first.")

    # ── Main analysis ──────────────────────────────────────────────

    def analyze(self):
        """Full analysis — pattern report + upgrade suggestions."""
        self._require_auth()

        print(f"\n{B}{'═'*60}{RST}")
        print(f"{W}{BOLD}  M7 Brain Analysis Report{RST}")
        print(f"{B}{'═'*60}{RST}\n")

        # Load all session data and learn
        self._learn_from_all_sessions()

        # Pattern report
        report = self.patterns.get_full_report()
        self._print_pattern_report(report)

        # Tool knowledge
        self._check_all_tools()

        # Save analysis to encrypted DB
        self._save_to_db("last_analysis", {
            "timestamp" : datetime.now().isoformat(),
            "report"    : report,
        })

        # Run full analyzer
        print(f"\n{B}━━━ Running Full AI Analyzer ━━━{RST}\n")
        M7Analyzer().run()

    def _learn_from_all_sessions(self):
        """Load all sessions and feed to pattern engine."""
        if not os.path.isdir(SESSIONS_DIR):
            return
        count = 0
        for fname in sorted(os.listdir(SESSIONS_DIR)):
            if not fname.endswith(".json"): continue
            try:
                with open(os.path.join(SESSIONS_DIR, fname)) as f:
                    session = json.load(f)
                self.patterns.learn_from_session(session)
                count += 1
            except Exception:
                pass
        if count:
            print(f"{C}[*]{RST} Learned from {count} scan sessions")

    def _print_pattern_report(self, report: dict):
        print(f"{B}━━━ Tool Timing Patterns ━━━{RST}")
        slow = report.get("slow_tools", [])
        if slow:
            for t in slow:
                trend = "↑" if t.get("trend")=="increasing" else "→"
                print(f"  {Y}[SLOW]{RST} {t['tool']:20s} avg: {t['avg_ms']//1000}s {trend}")
        else:
            print(f"  {G}All tools within normal timing{RST}")

        print(f"\n{B}━━━ Weak Steps (low output) ━━━{RST}")
        weak = report.get("weak_steps", [])
        if weak:
            for w in weak:
                print(f"  {Y}[WEAK]{RST} {w['step']:20s} avg output: {w['avg_output']:.1f} lines")
        else:
            print(f"  {G}All steps producing reasonable output{RST}")

        print(f"\n{B}━━━ Frequently Missed Steps ━━━{RST}")
        missed = report.get("missed_steps", [])
        if missed:
            for m in missed:
                print(f"  {R}[MISSED {m['miss_count']}x]{RST} {m['step']}")
        else:
            print(f"  {G}No steps repeatedly missed{RST}")

        print(f"\n{B}━━━ What Brain Forgot ━━━{RST}")
        forgotten = report.get("forgotten_checks", [])
        if forgotten:
            for f in sorted(forgotten, key=lambda x: x.get("seen_count",1), reverse=True)[:5]:
                count = f.get("seen_count", 1)
                print(f"  {R}[{count}x forgotten]{RST} {f['message']}")
                print(f"  {DIM}  Fix: {f['fix']}{RST}")
        else:
            print(f"  {G}No recurring forgotten checks{RST}")

    def _check_all_tools(self):
        print(f"\n{B}━━━ Tool Health Check ━━━{RST}")
        for tool in self.cmd_engine.list_all_tools():
            result = self.cmd_engine.check_tool(tool)
            if result["installed"]:
                ver = f"({result['version'][:30]})" if result.get("version") else ""
                print(f"  {G}[✓]{RST} {tool:20s} {DIM}{ver}{RST}")
            else:
                err = result.get("error","not found")
                print(f"  {R}[✗]{RST} {tool:20s} {Y}{err}{RST}")

    # ── Interactive Brain Console ──────────────────────────────────

    def interactive_mode(self):
        """
        Interactive console — brain se seedha baat karo.
        Ask it about tools, patterns, commands.
        """
        self._require_auth()

        print(f"""
{B}  ╔══════════════════════════════════════════════════╗{RST}
{B}  ║{RST}  {W}{BOLD}M7 Brain Console{RST}                               {B}║{RST}
{B}  ║{RST}  {DIM}Commands: analyze | tools | how <tool> | fix <cmd>{RST}  {B}║{RST}
{B}  ║{RST}  {DIM}          patterns | forgot | status | exit{RST}         {B}║{RST}
{B}  ╚══════════════════════════════════════════════════╝{RST}
""")

        while True:
            try:
                cmd = input(f"{C}m7brain>{RST} ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                print(f"\n{DIM}Brain console closed.{RST}")
                break

            if not cmd:
                continue

            elif cmd == "exit":
                break

            elif cmd == "analyze":
                self.analyze()

            elif cmd == "patterns":
                report = self.patterns.get_full_report()
                self._print_pattern_report(report)

            elif cmd == "forgot":
                forgotten = self.patterns.get_forgotten_checks()
                if forgotten:
                    print(f"\n{Y}Brain forgot these checks:{RST}")
                    for f in forgotten:
                        print(f"  [{f.get('seen_count',1)}x] {f['message']}")
                        print(f"  {DIM}Fix: {f['fix']}{RST}\n")
                else:
                    print(f"{G}No forgotten checks recorded yet.{RST}")

            elif cmd == "tools":
                print(f"\n{C}All tools in knowledge base:{RST}")
                for tool in self.cmd_engine.list_all_tools():
                    result = self.cmd_engine.check_tool(tool)
                    status = f"{G}✓{RST}" if result["installed"] else f"{R}✗{RST}"
                    print(f"  {status} {tool}")

            elif cmd.startswith("how "):
                tool = cmd[4:].strip()
                cmds = TOOL_KB.get(tool, {}).get("commands", {})
                if cmds:
                    print(f"\n{C}Commands for {tool}:{RST}")
                    for mode, template in cmds.items():
                        print(f"  {W}{mode:15s}{RST}: {template}")
                    fmt = self.cmd_engine.get_input_format(tool)
                    print(f"\n  {DIM}Input format: {fmt}{RST}")
                    docs = self.cmd_engine.get_docs_url(tool)
                    if docs:
                        print(f"  {DIM}Docs: {docs}{RST}")
                else:
                    print(f"{Y}Unknown tool: {tool}{RST}")

            elif cmd.startswith("fix "):
                # Try to detect tool from command
                command = cmd[4:].strip()
                first_word = command.split()[0] if command.split() else ""
                tool = first_word if first_word in TOOL_KB else None
                if tool:
                    fixed, was_fixed, issue = self.cmd_engine.validate_command(tool, command)
                    if was_fixed:
                        print(f"\n{Y}Issue:{RST} {issue}")
                        print(f"{G}Fixed:{RST} {fixed}")
                    else:
                        print(f"{G}Command looks correct.{RST}")
                else:
                    print(f"{Y}Cannot detect tool from command. Specify tool name at start.{RST}")

            elif cmd == "status":
                self._print_status()

            else:
                print(f"{DIM}Unknown command. Type 'exit' to quit.{RST}")

    def _print_status(self):
        n_sessions = 0
        if os.path.isdir(SESSIONS_DIR):
            n_sessions = len([f for f in os.listdir(SESSIONS_DIR) if f.endswith(".json")])

        print(f"""
{B}  Status{RST}
  Total scans   : {W}{self.patterns.patterns.get('total_scans', 0)}{RST}
  Session files : {W}{n_sessions}{RST}
  DB encrypted  : {G}yes{RST}
  Brain auth    : {G}active{RST}
  Tools in KB   : {W}{len(TOOL_KB)}{RST}
""")

    # ── Encrypted DB operations ────────────────────────────────────

    def _save_to_db(self, key: str, value):
        try:
            self.db.update(key, value)
        except AccessDenied:
            pass

    def save_custom_note(self, key: str, note: str):
        """Admin notes save karo encrypted DB mein."""
        self._require_auth()
        self.db.update(f"note_{key}", {
            "content"  : note,
            "timestamp": datetime.now().isoformat(),
        })

    def read_notes(self) -> dict:
        """Saare notes padho."""
        self._require_auth()
        data = self.db.read()
        return {k: v for k, v in data.items() if k.startswith("note_")}


# ── CLI entrypoint ────────────────────────────────────────────────

def main():
    brain = M7Brain()

    if "--analyze" in sys.argv:
        if brain.authenticate():
            brain.analyze()

    elif "--console" in sys.argv or "--brain" in sys.argv:
        if brain.authenticate():
            brain.interactive_mode()

    elif "--check-tools" in sys.argv:
        if brain.authenticate():
            brain._check_all_tools()

    elif "--patterns" in sys.argv:
        if brain.authenticate():
            brain._learn_from_all_sessions()
            report = brain.patterns.get_full_report()
            brain._print_pattern_report(report)

    else:
        print(f"Usage: python3 -m ai.brain [--analyze|--console|--patterns|--check-tools]")


if __name__ == "__main__":
    main()
