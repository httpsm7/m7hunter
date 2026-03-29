#!/usr/bin/env python3
# ai/brain_viewer.py — M7Hunter v5.0 Brain Data Viewer
# sudo m7hunter --open-your-brain
# View all stored intelligence data after authentication
# MilkyWay Intelligence | Author: Sharlix

import os
import json
import time
from ai.secure_db import SecureDB, AccessDenied

R="\033[91m"; B="\033[34m"; C="\033[96m"; Y="\033[93m"
G="\033[92m"; W="\033[97m"; DIM="\033[2m"; RST="\033[0m"; BOLD="\033[1m"

SESSIONS_DIR = os.path.expanduser("~/.m7hunter/sessions/")
PATTERNS_FILE= os.path.expanduser("~/.m7hunter/patterns.json")
TRAINING_FILE= os.path.expanduser("~/.m7hunter/training_data.jsonl")
AUDIT_DIR    = os.path.expanduser("~/.m7hunter/audit/")


class BrainViewer:
    """
    V5 Brain Viewer — View all stored M7Hunter intelligence data.
    Requires admin authentication before showing any data.

    Command: sudo m7hunter --open-your-brain

    Shows:
    - Encrypted DB contents (admin notes, analyses)
    - All session data (scan history)
    - Pattern learning data (tool timings, payload success rates)
    - AI training data stats
    - Audit logs
    - Export options
    """

    def __init__(self):
        self.db = SecureDB()
        self._authenticated = False

    def run(self):
        self._print_header()

        # Authenticate
        print(f"{Y}[!]{RST} Brain data access requires admin authentication\n")
        ok = self.db.authenticate()
        if not ok:
            print(f"\n{R}[✗]{RST} Authentication failed. Access denied.\n")
            return

        self._authenticated = True
        print(f"\n{G}[✓]{RST} Authentication successful. Welcome, admin.\n")
        time.sleep(0.5)

        self._interactive_menu()

    def _interactive_menu(self):
        while True:
            print(f"""
{B}  ╔══════════════════════════════════════════════════════╗{RST}
{B}  ║{RST}  {W}{BOLD}M7Hunter Brain Viewer v5.0{RST}                        {B}║{RST}
{B}  ╠══════════════════════════════════════════════════════╣{RST}
{B}  ║{RST}  {C}1.{RST} View encrypted DB data                           {B}║{RST}
{B}  ║{RST}  {C}2.{RST} View scan sessions (history)                     {B}║{RST}
{B}  ║{RST}  {C}3.{RST} View pattern learning data                       {B}║{RST}
{B}  ║{RST}  {C}4.{RST} View AI training data stats                      {B}║{RST}
{B}  ║{RST}  {C}5.{RST} View audit logs                                  {B}║{RST}
{B}  ║{RST}  {C}6.{RST} View payload success rates                       {B}║{RST}
{B}  ║{RST}  {C}7.{RST} View top findings across all scans               {B}║{RST}
{B}  ║{RST}  {C}8.{RST} Export all data to JSON                         {B}║{RST}
{B}  ║{RST}  {C}9.{RST} Add admin note                                  {B}║{RST}
{B}  ║{RST}  {C}0.{RST} Exit                                            {B}║{RST}
{B}  ╚══════════════════════════════════════════════════════╝{RST}
""")
            try:
                choice = input(f"{C}brain>{RST} ").strip()
            except (KeyboardInterrupt, EOFError):
                print(f"\n{DIM}Exiting Brain Viewer.{RST}")
                break

            if choice == "0":
                break
            elif choice == "1": self._view_db()
            elif choice == "2": self._view_sessions()
            elif choice == "3": self._view_patterns()
            elif choice == "4": self._view_training()
            elif choice == "5": self._view_audit()
            elif choice == "6": self._view_payloads()
            elif choice == "7": self._view_top_findings()
            elif choice == "8": self._export_all()
            elif choice == "9": self._add_note()
            else:
                print(f"{Y}Unknown option.{RST}")

    # ── 1. Encrypted DB ──────────────────────────────────────────────
    def _view_db(self):
        print(f"\n{B}━━━ Encrypted DB Contents ━━━{RST}")
        try:
            data = self.db.read()
            if not data:
                print(f"  {DIM}No data stored yet.{RST}")
                return
            for key, value in data.items():
                if isinstance(value, dict):
                    print(f"\n  {C}{key}:{RST}")
                    for k2, v2 in value.items():
                        v2_str = str(v2)[:100]
                        print(f"    {W}{k2}{RST}: {DIM}{v2_str}{RST}")
                else:
                    v_str = str(value)[:100]
                    print(f"  {C}{key}{RST}: {W}{v_str}{RST}")
        except AccessDenied as e:
            print(f"  {R}Access error: {e}{RST}")

    # ── 2. Sessions ──────────────────────────────────────────────────
    def _view_sessions(self):
        print(f"\n{B}━━━ Scan Sessions ━━━{RST}")
        if not os.path.isdir(SESSIONS_DIR):
            print(f"  {DIM}No sessions yet. Run a scan first.{RST}")
            return
        files = sorted(os.listdir(SESSIONS_DIR))
        files = [f for f in files if f.endswith(".json")]
        print(f"  Total sessions: {W}{len(files)}{RST}\n")
        for fname in files[-20:]:  # Last 20
            path = os.path.join(SESSIONS_DIR, fname)
            try:
                data = json.load(open(path))
                target   = data.get("target","?")
                mode     = data.get("scan_mode","?")
                findings = len(data.get("findings",[]))
                duration = data.get("timing",{}).get("total_sec",0)
                steps    = list(data.get("steps",{}).keys())
                print(f"  {G}►{RST} {W}{target}{RST} [{mode}] | "
                      f"{R}{findings}{RST} findings | "
                      f"{DIM}{duration}s | {len(steps)} steps{RST}")
            except Exception:
                print(f"  {Y}[unreadable]{RST} {fname}")

    # ── 3. Patterns ──────────────────────────────────────────────────
    def _view_patterns(self):
        print(f"\n{B}━━━ Pattern Learning Data ━━━{RST}")
        if not os.path.isfile(PATTERNS_FILE):
            print(f"  {DIM}No patterns yet. Run more scans.{RST}")
            return
        data = json.load(open(PATTERNS_FILE))
        print(f"  Total scans     : {W}{data.get('total_scans',0)}{RST}")
        print(f"  Tools tracked   : {W}{len(data.get('tool_timings',{}))}{RST}")
        print(f"  Steps tracked   : {W}{len(data.get('step_outputs',{}))}{RST}")
        print(f"  Learned fixes   : {W}{len(data.get('learned_fixes',[]))}{RST}")
        print(f"  Missed steps    : {W}{len(data.get('missed_steps',{}))}{RST}")

        print(f"\n  {C}Tool Timings (avg ms):{RST}")
        timings = data.get("tool_timings", {})
        for tool, times in sorted(timings.items(), key=lambda x: sum(x[1])/max(len(x[1]),1), reverse=True)[:10]:
            avg = int(sum(times)/max(len(times),1))
            bar_len = min(int(avg/5000), 30)
            bar = "█" * bar_len
            col = R if avg > 120000 else Y if avg > 60000 else G
            print(f"    {col}{tool:20s}{RST} {bar} {avg//1000}s")

        print(f"\n  {C}Missed Critical Steps:{RST}")
        for step, count in data.get("missed_steps",{}).items():
            print(f"    {Y}{step:20s}{RST} missed {count}x")

    # ── 4. Training Data ─────────────────────────────────────────────
    def _view_training(self):
        print(f"\n{B}━━━ AI Training Data ━━━{RST}")
        if not os.path.isfile(TRAINING_FILE):
            print(f"  {DIM}No training data yet. Run --analyze after scans.{RST}")
            return
        types = {}
        total = 0
        with open(TRAINING_FILE) as f:
            for line in f:
                try:
                    ex = json.loads(line)
                    t  = ex.get("type","unknown")
                    types[t] = types.get(t,0) + 1
                    total += 1
                except Exception:
                    pass
        print(f"  Total examples : {W}{total}{RST}")
        print(f"  Target (500+)  : {G if total>=500 else Y}{total}/500{RST}\n")
        for t, count in sorted(types.items(), key=lambda x: x[1], reverse=True):
            bar = "█" * min(int(count/5), 20)
            print(f"  {C}{t:30s}{RST} {bar} {count}")

    # ── 5. Audit Logs ────────────────────────────────────────────────
    def _view_audit(self):
        print(f"\n{B}━━━ Audit Logs ━━━{RST}")
        if not os.path.isdir(AUDIT_DIR):
            print(f"  {DIM}No audit logs yet.{RST}")
            return
        files = sorted([f for f in os.listdir(AUDIT_DIR) if f.endswith(".jsonl")])
        print(f"  Total audit logs: {W}{len(files)}{RST}\n")
        for fname in files[-10:]:
            path = os.path.join(AUDIT_DIR, fname)
            events = {}
            scan_id = "?"
            target  = "?"
            try:
                with open(path) as f:
                    for line in f:
                        entry = json.loads(line)
                        ev = entry.get("event","")
                        events[ev] = events.get(ev,0) + 1
                        if ev == "scan_start":
                            scan_id = entry.get("data",{}).get("scan_id","?")
                            target  = entry.get("data",{}).get("target","?")
            except Exception:
                pass
            print(f"  {C}[{scan_id}]{RST} {W}{target}{RST}")
            print(f"    steps:{events.get('step_start',0)} "
                  f"findings:{events.get('finding',0)} "
                  f"fp_caught:{events.get('false_positive_caught',0)}")

    # ── 6. Payload success rates ─────────────────────────────────────
    def _view_payloads(self):
        print(f"\n{B}━━━ Payload Success Rates ━━━{RST}")
        learned_file = os.path.expanduser("~/.m7hunter/learned_patterns.json")
        if not os.path.isfile(learned_file):
            print(f"  {DIM}No payload data yet.{RST}")
            return
        data  = json.load(open(learned_file))
        rates = data.get("payload_success_rates", {})
        if not rates:
            print(f"  {DIM}No payload data yet.{RST}")
            return
        # Sort by success rate
        sorted_rates = sorted(rates.items(), key=lambda x: x[1], reverse=True)
        print(f"  {C}Top payloads by success rate:{RST}\n")
        for ph, rate in sorted_rates[:20]:
            bar = "█" * int(rate * 20)
            col = G if rate > 0.7 else Y if rate > 0.3 else R
            # Decode hash → we stored hash, so show hash only
            print(f"  {col}{bar:20s}{RST} {rate:.0%} (hash: {ph})")

    # ── 7. Top findings ──────────────────────────────────────────────
    def _view_top_findings(self):
        print(f"\n{B}━━━ Top Findings Across All Scans ━━━{RST}")
        all_findings = []
        for root, dirs, files in os.walk("results"):
            for fname in files:
                if fname.endswith("_findings.json"):
                    try:
                        data = json.load(open(os.path.join(root, fname)))
                        for f in data.get("findings", []):
                            f["_source"] = fname
                            all_findings.append(f)
                    except Exception:
                        pass

        if not all_findings:
            if os.path.isdir(SESSIONS_DIR):
                for fname in os.listdir(SESSIONS_DIR):
                    try:
                        data = json.load(open(os.path.join(SESSIONS_DIR, fname)))
                        all_findings.extend(data.get("findings", []))
                    except Exception:
                        pass

        if not all_findings:
            print(f"  {DIM}No findings yet. Run scans first.{RST}")
            return

        # Sort by severity
        sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
        all_findings.sort(key=lambda x: sev_order.get(x.get("severity","info"),5))

        print(f"  Total: {W}{len(all_findings)}{RST} findings across all scans\n")
        for f in all_findings[:30]:
            sev  = f.get("severity","info")
            vt   = f.get("type","?")
            url  = f.get("url","?")[:60]
            col  = {
                "critical": f"{R}{BOLD}",
                "high"    : R,
                "medium"  : Y,
                "low"     : G,
                "info"    : C,
            }.get(sev, W)
            print(f"  {col}[{sev.upper():8s}]{RST} {W}{vt:25s}{RST} {DIM}{url}{RST}")

    # ── 8. Export ────────────────────────────────────────────────────
    def _export_all(self):
        print(f"\n{B}━━━ Export All Brain Data ━━━{RST}")
        export = {
            "exported_at" : time.strftime("%Y-%m-%d %H:%M:%S"),
            "db_data"     : {},
            "sessions"    : [],
            "patterns"    : {},
            "training_stats": {},
        }
        # DB
        try:
            export["db_data"] = self.db.read()
        except Exception:
            pass
        # Sessions
        if os.path.isdir(SESSIONS_DIR):
            for fname in os.listdir(SESSIONS_DIR):
                try:
                    export["sessions"].append(
                        json.load(open(os.path.join(SESSIONS_DIR, fname))))
                except Exception:
                    pass
        # Patterns
        if os.path.isfile(PATTERNS_FILE):
            export["patterns"] = json.load(open(PATTERNS_FILE))

        out = os.path.expanduser("~/.m7hunter/brain_export.json")
        with open(out, "w") as f:
            json.dump(export, f, indent=2)
        print(f"  {G}[✓]{RST} Exported to: {W}{out}{RST}")
        print(f"  {DIM}Size: {os.path.getsize(out)//1024} KB{RST}")

    # ── 9. Add note ──────────────────────────────────────────────────
    def _add_note(self):
        print(f"\n{B}━━━ Add Admin Note ━━━{RST}")
        key  = input(f"  Note key (e.g. target_name): ").strip()
        note = input(f"  Note content: ").strip()
        if key and note:
            try:
                self.db.update(f"note_{key}", {
                    "content"  : note,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                })
                print(f"  {G}[✓]{RST} Note saved to encrypted DB.")
            except AccessDenied as e:
                print(f"  {R}Error: {e}{RST}")

    # ── Header ───────────────────────────────────────────────────────
    def _print_header(self):
        print(f"""
{B}  ╔══════════════════════════════════════════════════════╗{RST}
{B}  ║{RST}  {W}{BOLD}M7Hunter v5.0 — Brain Viewer{RST}                      {B}║{RST}
{B}  ║{RST}  {DIM}View all stored intelligence data{RST}                  {B}║{RST}
{B}  ║{RST}  {R}🔒 Admin authentication required{RST}                   {B}║{RST}
{B}  ╚══════════════════════════════════════════════════════╝{RST}
""")
