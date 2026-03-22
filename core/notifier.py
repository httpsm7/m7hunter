#!/usr/bin/env python3
# core/notifier.py — Telegram + Discord alerts (pure stdlib, no requests)
# MilkyWay Intelligence | Author: Sharlix

import urllib.request
import urllib.parse
import json
import threading
import time

SEV_EMOJI = {
    "critical": "🔴",
    "high"    : "🟠",
    "medium"  : "🟡",
    "low"     : "🟢",
    "info"    : "🔵",
}

class Notifier:
    def __init__(self, telegram_token="", telegram_chat="",
                 discord_webhook="", log=None):
        self.tg_token   = telegram_token or ""
        self.tg_chat    = telegram_chat  or ""
        self.dc_webhook = discord_webhook or ""
        self.log        = log
        self.enabled    = bool(self.tg_token and self.tg_chat) or bool(self.dc_webhook)
        self._lock      = threading.Lock()

    def send_finding(self, sev: str, vuln_type: str,
                     url: str, detail: str = "", tool: str = ""):
        if not self.enabled: return
        if sev.lower() not in ("critical", "high"): return
        emoji = SEV_EMOJI.get(sev.lower(), "⚪")
        msg = (
            f"{emoji} *M7Hunter v3.0 — New Finding*\n"
            f"Severity : `{sev.upper()}`\n"
            f"Type     : `{vuln_type}`\n"
            f"URL      : `{url[:200]}`\n"
            f"Detail   : `{detail[:150]}`\n"
            f"Tool     : `{tool}`"
        )
        threading.Thread(target=self._dispatch, args=(msg,), daemon=True).start()

    def send_message(self, msg: str):
        if not self.enabled: return
        threading.Thread(target=self._dispatch, args=(msg,), daemon=True).start()

    def send_scan_start(self, target: str):
        self.send_message(f"🚀 *M7Hunter v3.0*\nScan started: `{target}`")

    def send_scan_done(self, target: str, findings: int, elapsed: float):
        self.send_message(
            f"✅ *M7Hunter v3.0*\n"
            f"Scan complete: `{target}`\n"
            f"Findings: `{findings}` | Time: `{elapsed:.0f}s`"
        )

    def _dispatch(self, msg: str):
        if self.tg_token and self.tg_chat:
            self._telegram(msg)
        if self.dc_webhook:
            self._discord(msg)

    def _telegram(self, msg: str):
        try:
            url  = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
            data = urllib.parse.urlencode({
                "chat_id"   : self.tg_chat,
                "text"      : msg,
                "parse_mode": "Markdown",
            }).encode()
            req  = urllib.request.Request(url, data=data, method="POST")
            urllib.request.urlopen(req, timeout=10)
        except Exception as e:
            if self.log:
                self.log.warn(f"Telegram alert failed: {e}")

    def _discord(self, msg: str):
        try:
            # Convert Markdown to plain text for Discord
            clean   = msg.replace("*", "**").replace("`", "`")
            payload = json.dumps({"content": clean}).encode()
            req     = urllib.request.Request(
                self.dc_webhook,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception as e:
            if self.log:
                self.log.warn(f"Discord alert failed: {e}")
