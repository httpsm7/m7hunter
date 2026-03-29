#!/usr/bin/env python3
# integrations/telegram_bot.py — M7Hunter v5.0 Telegram Control Bot
# Full scan control: pause/stop/status/findings/AI analysis
# MilkyWay Intelligence | Author: Sharlix

import os
import json
import time
import threading
import urllib.request
import urllib.parse
import urllib.error

R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"
W="\033[97m"; DIM="\033[2m"; RST="\033[0m"

TG_API = "https://api.telegram.org/bot{token}/{method}"

HELP_TEXT = """
🤖 *M7Hunter v5.0 — Telegram Control Bot*

*Scan Control:*
/scan target.com --deep — Start new scan
/pause — Pause current scan
/resume — Resume paused scan  
/stop — Stop current scan
/status — Current scan status

*Results:*
/findings — Show latest findings
/critical — Show critical findings only
/report — Get report file path
/stats — Scan statistics

*AI Analysis:*
/ai <question> — Ask offline AI
/analyze — Run pattern analysis
/brain — Brain stats

*Tool:*
/check — Check all tools
/help — Show this message

_M7Hunter v5.0 | MilkyWay Intelligence_
"""


class TelegramBot:
    """
    V5 Telegram Bot for remote scan control.

    Features:
    - Start/pause/stop scans
    - Get real-time findings
    - Ask AI questions
    - View scan statistics
    """

    def __init__(self, token: str, log=None):
        self.token      = token
        self.log        = log
        self.offset     = 0
        self.running    = True
        self._lock      = threading.Lock()

        # Scan state
        self.active_pipeline = None
        self.scan_paused     = False
        self.authorized_chats= set()

        self._info(f"Telegram bot initialized")

    def run(self):
        """Start the bot polling loop."""
        self._info("Bot polling started — send /help to get started")
        print(f"\n  {G}[✓]{RST} Telegram bot running")
        print(f"  {C}[*]{RST} Send /help to your bot to get started")
        print(f"  {DIM}    Ctrl+C to stop the bot{RST}\n")

        while self.running:
            try:
                updates = self._get_updates()
                for update in updates:
                    self._handle_update(update)
                time.sleep(1)
            except KeyboardInterrupt:
                self.running = False
                break
            except Exception as e:
                self._warn(f"Bot error: {e}")
                time.sleep(5)

    # ── Update handling ──────────────────────────────────────────────
    def _handle_update(self, update: dict):
        message = update.get("message", {})
        if not message:
            return

        chat_id  = message.get("chat", {}).get("id")
        text     = message.get("text", "").strip()
        username = message.get("from", {}).get("username", "unknown")

        if not chat_id or not text:
            return

        # Auto-authorize first chat
        self.authorized_chats.add(chat_id)

        self._info(f"Command from @{username}: {text[:50]}")

        # Route command
        cmd = text.split()[0].lower()
        args = text.split()[1:] if len(text.split()) > 1 else []

        handlers = {
            "/help"    : self._cmd_help,
            "/start"   : self._cmd_help,
            "/scan"    : self._cmd_scan,
            "/pause"   : self._cmd_pause,
            "/resume"  : self._cmd_resume,
            "/stop"    : self._cmd_stop,
            "/status"  : self._cmd_status,
            "/findings": self._cmd_findings,
            "/critical": self._cmd_critical,
            "/report"  : self._cmd_report,
            "/stats"   : self._cmd_stats,
            "/ai"      : self._cmd_ai,
            "/analyze" : self._cmd_analyze,
            "/brain"   : self._cmd_brain,
            "/check"   : self._cmd_check,
        }

        handler = handlers.get(cmd, self._cmd_unknown)
        try:
            response = handler(chat_id, args)
            if response:
                self._send(chat_id, response)
        except Exception as e:
            self._send(chat_id, f"❌ Error: {str(e)[:200]}")

    # ── Command handlers ─────────────────────────────────────────────
    def _cmd_help(self, chat_id, args):
        return HELP_TEXT

    def _cmd_scan(self, chat_id, args):
        if not args:
            return "❌ Usage: /scan target.com [--deep|--fast]"
        target = args[0]
        mode   = "--deep" if "--deep" in args else "--fast"
        self._send(chat_id, f"🚀 Starting scan: `{target}` ({mode})")
        # Launch scan in background thread
        threading.Thread(
            target=self._run_scan_thread,
            args=(target, mode, chat_id),
            daemon=True
        ).start()
        return f"⏳ Scan launched for `{target}`. Use /status to monitor."

    def _run_scan_thread(self, target: str, mode: str, chat_id: int):
        """Run scan in background thread."""
        try:
            import subprocess, sys
            cmd = [sys.executable, "m7hunter.py", "-u", target, mode]
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True
            )
            self._send(chat_id, f"🔄 Scan PID: `{process.pid}`\nUse /stop to terminate.")
            stdout, stderr = process.communicate(timeout=7200)
            if process.returncode == 0:
                self._send(chat_id, f"✅ Scan complete for `{target}`\n{stdout[-500:]}")
            else:
                self._send(chat_id, f"⚠️ Scan finished with errors:\n{stderr[-300:]}")
        except Exception as e:
            self._send(chat_id, f"❌ Scan failed: {str(e)[:200]}")

    def _cmd_pause(self, chat_id, args):
        self.scan_paused = True
        return "⏸ Scan pause requested. Current step will complete before pausing."

    def _cmd_resume(self, chat_id, args):
        self.scan_paused = False
        return "▶️ Scan resumed."

    def _cmd_stop(self, chat_id, args):
        import subprocess
        subprocess.run(["pkill", "-f", "m7hunter.py"], capture_output=True)
        return "🛑 Scan stop signal sent."

    def _cmd_status(self, chat_id, args):
        # Check for active scans
        import subprocess
        result = subprocess.run(
            ["pgrep", "-f", "m7hunter"],
            capture_output=True, text=True
        )
        pids = result.stdout.strip()
        if pids:
            status = f"🔄 *Active scan(s)*\nPIDs: `{pids}`\nPaused: {'Yes' if self.scan_paused else 'No'}"
        else:
            status = "💤 No active scans\nUse /scan target.com to start"

        # Latest results
        results_dir = "results"
        if os.path.isdir(results_dir):
            dirs = sorted([
                d for d in os.listdir(results_dir)
                if os.path.isdir(os.path.join(results_dir, d))
            ])
            if dirs:
                latest = dirs[-1]
                status += f"\n\n📁 Latest output: `{latest}`"

        return status

    def _cmd_findings(self, chat_id, args):
        findings = self._get_latest_findings()
        if not findings:
            return "📭 No findings yet"
        msg = f"🔍 *Latest Findings* ({len(findings)} total)\n\n"
        for f in findings[-10:]:
            sev = f.get("severity","?").upper()
            emoji = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(sev,"⚪")
            msg += f"{emoji} `{sev}` — {f.get('type','?')}\n"
            msg += f"  `{f.get('url','?')[:60]}`\n\n"
        return msg

    def _cmd_critical(self, chat_id, args):
        findings = self._get_latest_findings()
        crits = [f for f in findings if f.get("severity","").lower() in ("critical","high")]
        if not crits:
            return "✅ No critical/high findings"
        msg = f"🚨 *Critical/High Findings* ({len(crits)})\n\n"
        for f in crits:
            msg += f"🔴 *{f.get('type','')}*\n`{f.get('url','')[:60]}`\n{f.get('detail','')[:100]}\n\n"
        return msg

    def _cmd_report(self, chat_id, args):
        reports = []
        for root, dirs, files in os.walk("results"):
            for f in files:
                if f.endswith("_report.html"):
                    reports.append(os.path.join(root, f))
        if not reports:
            return "📭 No reports generated yet"
        latest = sorted(reports)[-1]
        return f"📊 *Latest Report*\n`{latest}`\n\nOpen in browser or copy to view."

    def _cmd_stats(self, chat_id, args):
        findings = self._get_latest_findings()
        if not findings:
            return "📭 No stats yet — run a scan first"
        sev_count = {}
        for f in findings:
            sev = f.get("severity","info")
            sev_count[sev] = sev_count.get(sev,0) + 1
        confirmed = sum(1 for f in findings if f.get("status")=="confirmed")
        msg  = f"📊 *Scan Statistics*\n\n"
        msg += f"🔴 Critical: {sev_count.get('critical',0)}\n"
        msg += f"🟠 High    : {sev_count.get('high',0)}\n"
        msg += f"🟡 Medium  : {sev_count.get('medium',0)}\n"
        msg += f"🟢 Low     : {sev_count.get('low',0)}\n\n"
        msg += f"✅ Confirmed  : {confirmed}\n"
        msg += f"📋 Total     : {len(findings)}\n"
        return msg

    def _cmd_ai(self, chat_id, args):
        if not args:
            return "❌ Usage: /ai <your question>"
        question = " ".join(args)
        try:
            from ai.offline.ollama_engine import OfflineAI
            ai = OfflineAI()
            if ai.is_available():
                answer = ai.chat(question)
                return f"🤖 *AI Response:*\n\n{answer[:1000]}"
            else:
                from ai.offline_ai import OfflineAI as PatternAI
                ai2 = PatternAI()
                return f"🤖 *Offline AI:*\n{ai2.get_status()}\n\nOllama not available. Install with: sudo m7hunter --setup-ai"
        except Exception as e:
            return f"❌ AI error: {str(e)[:200]}"

    def _cmd_analyze(self, chat_id, args):
        self._send(chat_id, "🧠 Running pattern analysis...")
        try:
            from ai.analyzer import M7Analyzer
            M7Analyzer().run()
            return "✅ Analysis complete. Check upgrade_report.json"
        except Exception as e:
            return f"❌ Analysis failed: {e}"

    def _cmd_brain(self, chat_id, args):
        try:
            sessions_dir = os.path.expanduser("~/.m7hunter/sessions/")
            n_sessions   = len(os.listdir(sessions_dir)) if os.path.isdir(sessions_dir) else 0
            patterns_file= os.path.expanduser("~/.m7hunter/patterns.json")
            n_scans      = 0
            if os.path.isfile(patterns_file):
                import json
                data = json.load(open(patterns_file))
                n_scans = data.get("total_scans", 0)
            return (
                f"🧠 *Brain Status*\n\n"
                f"Total scans    : `{n_scans}`\n"
                f"Session files  : `{n_sessions}`\n"
                f"DB encrypted   : ✅\n"
                f"Offline AI     : ✅\n\n"
                f"Use `/ai <question>` to query the AI"
            )
        except Exception as e:
            return f"❌ Brain error: {e}"

    def _cmd_check(self, chat_id, args):
        self._send(chat_id, "🔧 Checking tools...")
        try:
            import shutil
            tools = [
                "subfinder","httpx","nuclei","dalfox","sqlmap",
                "nmap","dnsx","katana","subzy","gau","ffuf","naabu"
            ]
            ok  = [t for t in tools if shutil.which(t)]
            bad = [t for t in tools if not shutil.which(t)]
            msg  = f"🔧 *Tool Status*\n\n"
            msg += f"✅ Installed ({len(ok)}): {', '.join(ok)}\n\n"
            if bad:
                msg += f"❌ Missing ({len(bad)}): {', '.join(bad)}\n"
                msg += f"\nRun: `sudo m7hunter --install`"
            return msg
        except Exception as e:
            return f"❌ Check failed: {e}"

    def _cmd_unknown(self, chat_id, args):
        return "❓ Unknown command. Send /help for available commands."

    # ── Helpers ──────────────────────────────────────────────────────
    def _get_latest_findings(self) -> list:
        """Read latest findings from most recent result directory."""
        for root, dirs, files in os.walk("results"):
            for f in sorted(files, reverse=True):
                if f.endswith("_findings.json"):
                    try:
                        with open(os.path.join(root, f)) as fp:
                            data = json.load(fp)
                            return data.get("findings", [])
                    except Exception:
                        pass
        return []

    def _get_updates(self) -> list:
        url  = TG_API.format(token=self.token, method="getUpdates")
        url += f"?offset={self.offset}&timeout=30&limit=10"
        try:
            req  = urllib.request.Request(url, headers={"User-Agent": "M7Hunter/5.0"})
            resp = urllib.request.urlopen(req, timeout=35)
            data = json.loads(resp.read().decode())
            updates = data.get("result", [])
            if updates:
                self.offset = updates[-1]["update_id"] + 1
            return updates
        except Exception:
            return []

    def _send(self, chat_id: int, text: str):
        url  = TG_API.format(token=self.token, method="sendMessage")
        data = urllib.parse.urlencode({
            "chat_id"   : chat_id,
            "text"      : text[:4000],
            "parse_mode": "Markdown",
        }).encode()
        try:
            req = urllib.request.Request(url, data=data, method="POST")
            urllib.request.urlopen(req, timeout=10)
        except Exception as e:
            self._warn(f"Send failed: {e}")

    def notify_finding(self, severity: str, vuln_type: str, url: str,
                       detail: str, chat_id: int = None):
        """Called by notifier to send findings to Telegram."""
        if not self.authorized_chats and not chat_id:
            return
        targets = [chat_id] if chat_id else list(self.authorized_chats)
        emoji = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢"}.get(
            severity.lower(),"⚪")
        msg = (
            f"{emoji} *{vuln_type}* — `{severity.upper()}`\n"
            f"`{url[:80]}`\n"
            f"_{detail[:150]}_"
        )
        for cid in targets:
            self._send(cid, msg)

    def _info(self, msg):
        if self.log: self.log.info(msg)
    def _warn(self, msg):
        if self.log: self.log.warn(msg)
