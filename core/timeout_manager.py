#!/usr/bin/env python3
# core/timeout_manager.py — Adaptive timeout per tool
# MilkyWay Intelligence | Author: Sharlix

import time

TOOL_TIMEOUTS = {
    "subfinder"   : {"default": 120,  "min": 60,   "max": 300},
    "amass"       : {"default": 300,  "min": 120,  "max": 600},
    "dnsx"        : {"default": 120,  "min": 60,   "max": 240},
    "httpx"       : {"default": 120,  "min": 60,   "max": 300},
    "gau"         : {"default": 180,  "min": 90,   "max": 360},
    "waybackurls" : {"default": 120,  "min": 60,   "max": 240},
    "katana"      : {"default": 300,  "min": 120,  "max": 600},
    "hakrawler"   : {"default": 180,  "min": 90,   "max": 360},
    "arjun"       : {"default": 240,  "min": 120,  "max": 480},
    "naabu"       : {"default": 300,  "min": 120,  "max": 600},
    "nmap"        : {"default": 600,  "min": 300,  "max": 1200},
    "masscan"     : {"default": 300,  "min": 120,  "max": 600},
    "nuclei"      : {"default": 1800, "min": 600,  "max": 3600},
    "dalfox"      : {"default": 300,  "min": 120,  "max": 600},
    "sqlmap"      : {"default": 600,  "min": 300,  "max": 1200},
    "ffuf"        : {"default": 300,  "min": 120,  "max": 600},
    "subzy"       : {"default": 120,  "min": 60,   "max": 240},
    "gowitness"   : {"default": 300,  "min": 120,  "max": 600},
    "wpscan"      : {"default": 300,  "min": 120,  "max": 600},
    "ssrf_engine" : {"default": 300,  "min": 120,  "max": 600},
    "ssti_engine" : {"default": 180,  "min": 60,   "max": 360},
    "jwt_engine"  : {"default": 120,  "min": 60,   "max": 240},
    "github_dork" : {"default": 180,  "min": 60,   "max": 360},
    "cloud_enum"  : {"default": 180,  "min": 60,   "max": 360},
    "trufflehog"  : {"default": 120,  "min": 60,   "max": 240},
    "kxss"        : {"default": 120,  "min": 60,   "max": 240},
    "default"     : {"default": 300,  "min": 120,  "max": 600},
}

class TimeoutManager:
    def __init__(self, base_multiplier=1.0):
        self.multiplier = base_multiplier
        self._history   = {}

    def get(self, tool_name: str) -> int:
        cfg      = TOOL_TIMEOUTS.get(tool_name, TOOL_TIMEOUTS["default"])
        base     = cfg["default"]
        adjusted = int(base * self.multiplier)
        hist     = self._history.get(tool_name, [])
        if len(hist) >= 2:
            timeout_rate = sum(1 for _, to in hist if to) / len(hist)
            if timeout_rate >= 0.5:
                adjusted = min(int(adjusted * 1.5), cfg["max"])
            elif timeout_rate == 0:
                avg_elapsed = sum(e for e, _ in hist) / len(hist)
                if avg_elapsed < base * 0.3:
                    adjusted = max(int(adjusted * 0.7), cfg["min"])
        return adjusted

    def record(self, tool_name: str, elapsed: float, timed_out: bool):
        self._history.setdefault(tool_name, [])
        self._history[tool_name].append((elapsed, timed_out))
        self._history[tool_name] = self._history[tool_name][-5:]

    def set_stealth(self):
        self.multiplier = 2.0

    def set_fast(self):
        self.multiplier = 0.7
