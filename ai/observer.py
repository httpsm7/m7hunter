#!/usr/bin/env python3
# ai/observer.py — M7 Observer
# Har scan ko andar se dekhta hai aur structured data collect karta hai
# Yahi data future AI training ka base banega
#
# MilkyWay Intelligence | Author: Sharlix

import os
import json
import time
import threading
import hashlib
from datetime import datetime

OBSERVER_DB = os.path.expanduser("~/.m7hunter/intelligence.json")
SESSIONS_DB = os.path.expanduser("~/.m7hunter/sessions/")


class M7Observer:
    """
    M7Hunter ka andar ka observer.

    Kya karta hai:
    - Har step ki timing, success/fail, findings record karta hai
    - Kaunse tools timeout hue, kaunse kaam aaye
    - Kaunsi vuln types kis target type pe mili
    - False positives track karta hai
    - Payload success rate record karta hai
    - Yeh sab ek structured JSON mein save karta hai
    - Analyzer baad mein isko pad ke upgrade suggestions deta hai
    """

    def __init__(self, pipeline=None):
        self.pipeline    = pipeline
        self.session_id  = self._gen_session_id()
        self.session_data = {
            "session_id"    : self.session_id,
            "timestamp"     : datetime.now().isoformat(),
            "target"        : getattr(pipeline, 'target', 'unknown') if pipeline else 'unknown',
            "scan_mode"     : self._get_mode(),
            "steps"         : {},       # step name -> StepRecord
            "findings"      : [],       # all findings with context
            "false_positives": [],      # manually marked false positives
            "tool_health"   : {},       # tool -> {success, timeout, fail, avg_ms}
            "payload_stats" : {},       # payload -> {tried, worked}
            "target_profile": {},       # what we learned about target tech stack
            "timing"        : {
                "start"     : time.time(),
                "end"       : None,
                "total_sec" : None,
            },
            "meta": {
                "m7_version" : "3.0.0",
                "os"         : os.uname().sysname if hasattr(os, 'uname') else 'unknown',
                "tor_used"   : False,
                "oob_used"   : False,
            }
        }
        self._lock = threading.Lock()
        os.makedirs(os.path.expanduser("~/.m7hunter/sessions/"), exist_ok=True)
        os.makedirs(os.path.expanduser("~/.m7hunter/"), exist_ok=True)

    def _gen_session_id(self):
        return hashlib.md5(
            f"{time.time()}{os.getpid()}".encode()
        ).hexdigest()[:12]

    def _get_mode(self):
        if not self.pipeline: return "unknown"
        args = self.pipeline.args
        if getattr(args, 'stealth', False): return "stealth"
        if getattr(args, 'deep', False):    return "deep"
        if getattr(args, 'quick', False):   return "quick"
        return "custom"

    # ── Step tracking ─────────────────────────────────────────────

    def step_start(self, step_name: str):
        with self._lock:
            self.session_data["steps"][step_name] = {
                "name"       : step_name,
                "start_time" : time.time(),
                "end_time"   : None,
                "duration_ms": None,
                "status"     : "running",   # running / success / failed / skipped
                "output_count": 0,          # lines in output file
                "tools_used" : [],
                "errors"     : [],
            }

    def step_end(self, step_name: str, status: str = "success",
                 output_count: int = 0, error: str = None):
        with self._lock:
            step = self.session_data["steps"].get(step_name)
            if not step: return
            end_time = time.time()
            step["end_time"]    = end_time
            step["duration_ms"] = int((end_time - step["start_time"]) * 1000)
            step["status"]      = status
            step["output_count"]= output_count
            if error:
                step["errors"].append(error)

    def record_tool_call(self, tool_name: str, success: bool,
                         duration_ms: int, timed_out: bool = False):
        """Record every shell tool call result."""
        with self._lock:
            if tool_name not in self.session_data["tool_health"]:
                self.session_data["tool_health"][tool_name] = {
                    "calls"     : 0,
                    "success"   : 0,
                    "timeout"   : 0,
                    "fail"      : 0,
                    "total_ms"  : 0,
                    "avg_ms"    : 0,
                }
            h = self.session_data["tool_health"][tool_name]
            h["calls"]    += 1
            h["total_ms"] += duration_ms
            h["avg_ms"]    = h["total_ms"] // h["calls"]
            if timed_out:
                h["timeout"] += 1
            elif success:
                h["success"] += 1
            else:
                h["fail"] += 1

    def record_finding(self, severity: str, vuln_type: str,
                       url: str, detail: str, tool: str,
                       payload: str = "", response_snippet: str = ""):
        """Record a finding with full context for AI training."""
        with self._lock:
            self.session_data["findings"].append({
                "severity"        : severity,
                "vuln_type"       : vuln_type,
                "url"             : url,
                "detail"          : detail,
                "tool"            : tool,
                "payload"         : payload,
                "response_snippet": response_snippet[:300] if response_snippet else "",
                "timestamp"       : datetime.now().isoformat(),
                "confirmed"       : True,   # default true, can be marked FP later
            })
            # Track payload success
            if payload:
                if payload not in self.session_data["payload_stats"]:
                    self.session_data["payload_stats"][payload] = {"tried":0,"worked":0}
                self.session_data["payload_stats"][payload]["worked"] += 1

    def record_payload_tried(self, payload: str):
        """Track that a payload was attempted (even if not successful)."""
        with self._lock:
            if payload not in self.session_data["payload_stats"]:
                self.session_data["payload_stats"][payload] = {"tried":0,"worked":0}
            self.session_data["payload_stats"][payload]["tried"] += 1

    def mark_false_positive(self, vuln_type: str, url: str, reason: str = ""):
        """User manually marks a finding as false positive."""
        with self._lock:
            # Find and mark the finding
            for f in self.session_data["findings"]:
                if f["vuln_type"] == vuln_type and f["url"] == url:
                    f["confirmed"] = False
                    break
            self.session_data["false_positives"].append({
                "vuln_type" : vuln_type,
                "url"       : url,
                "reason"    : reason,
                "timestamp" : datetime.now().isoformat(),
            })

    def record_tech_stack(self, url: str, technologies: list):
        """Record what technologies were detected on target."""
        with self._lock:
            self.session_data["target_profile"][url] = {
                "technologies": technologies,
                "timestamp"   : datetime.now().isoformat(),
            }

    def set_meta(self, key: str, value):
        with self._lock:
            self.session_data["meta"][key] = value

    # ── Save / Load ───────────────────────────────────────────────

    def save_session(self):
        """Save this session's data to disk."""
        self.session_data["timing"]["end"]       = time.time()
        self.session_data["timing"]["total_sec"] = round(
            self.session_data["timing"]["end"] - self.session_data["timing"]["start"], 1
        )

        # Save individual session file
        session_file = os.path.join(
            os.path.expanduser("~/.m7hunter/sessions/"),
            f"session_{self.session_id}.json"
        )
        with open(session_file, "w") as f:
            json.dump(self.session_data, f, indent=2)

        # Merge into master intelligence DB
        self._merge_into_master()
        return session_file

    def _merge_into_master(self):
        """Merge this session into the cumulative intelligence database."""
        master = {"sessions": [], "summary": {}}

        if os.path.isfile(OBSERVER_DB):
            try:
                with open(OBSERVER_DB) as f:
                    master = json.load(f)
            except Exception:
                pass

        # Append session summary
        master["sessions"].append({
            "session_id"     : self.session_id,
            "timestamp"      : self.session_data["timestamp"],
            "target"         : self.session_data["target"],
            "mode"           : self.session_data["scan_mode"],
            "total_findings" : len(self.session_data["findings"]),
            "false_positives": len(self.session_data["false_positives"]),
            "duration_sec"   : self.session_data["timing"]["total_sec"],
            "steps_run"      : list(self.session_data["steps"].keys()),
        })

        # Update cumulative summary
        self._update_summary(master)

        with open(OBSERVER_DB, "w") as f:
            json.dump(master, f, indent=2)

    def _update_summary(self, master: dict):
        """Build cumulative summary across all sessions."""
        all_sessions_dir = os.path.expanduser("~/.m7hunter/sessions/")
        vuln_counts    = {}
        tool_timeouts  = {}
        payload_wins   = {}
        total_scans    = 0
        total_findings = 0

        for fname in os.listdir(all_sessions_dir):
            if not fname.endswith(".json"): continue
            try:
                with open(os.path.join(all_sessions_dir, fname)) as f:
                    s = json.load(f)
                total_scans    += 1
                total_findings += len(s.get("findings", []))

                # Count vuln types
                for finding in s.get("findings", []):
                    vt = finding.get("vuln_type", "UNKNOWN")
                    vuln_counts[vt] = vuln_counts.get(vt, 0) + 1

                # Tool health
                for tool, health in s.get("tool_health", {}).items():
                    if tool not in tool_timeouts:
                        tool_timeouts[tool] = {"timeout": 0, "calls": 0}
                    tool_timeouts[tool]["timeout"] += health.get("timeout", 0)
                    tool_timeouts[tool]["calls"]   += health.get("calls", 0)

                # Payload wins
                for payload, stats in s.get("payload_stats", {}).items():
                    if payload not in payload_wins:
                        payload_wins[payload] = {"tried": 0, "worked": 0}
                    payload_wins[payload]["tried"]  += stats.get("tried", 0)
                    payload_wins[payload]["worked"] += stats.get("worked", 0)

            except Exception:
                continue

        # Top payloads by success rate
        top_payloads = sorted(
            [(p, s["worked"], s["tried"]) for p, s in payload_wins.items() if s["tried"] > 0],
            key=lambda x: x[1] / max(x[2], 1),
            reverse=True
        )[:20]

        # Tools that timeout most
        problematic_tools = [
            t for t, h in tool_timeouts.items()
            if h["calls"] > 0 and h["timeout"] / h["calls"] > 0.3
        ]

        master["summary"] = {
            "total_scans"      : total_scans,
            "total_findings"   : total_findings,
            "top_vuln_types"   : sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            "problematic_tools": problematic_tools,
            "top_payloads"     : top_payloads,
            "last_updated"     : datetime.now().isoformat(),
        }
