#!/usr/bin/env python3
# core/audit_logger.py — M7Hunter v5.0 Structured Audit Logger
# Every scan gets unique ID + full trace: request → payload → response → decision
# MilkyWay Intelligence | Author: Sharlix

import os
import json
import time
import uuid
import hashlib
import threading


AUDIT_DIR = os.path.expanduser("~/.m7hunter/audit/")


class AuditLogger:
    """
    V5 Structured Audit Logger.

    Every scan gets:
    - Unique scan_id (UUID)
    - JSONL audit log (one event per line)
    - Full trace: step_start → command → finding → decision

    Log format (each line is valid JSON):
    {
      "scan_id"  : "abc123",
      "event"    : "finding",
      "timestamp": "2026-03-29 12:00:00",
      "data"     : { ... }
    }
    """

    def __init__(self, target: str, log_dir: str = None):
        self.target   = target
        self.scan_id  = str(uuid.uuid4())[:12]
        self.start_ts = time.time()
        self._lock    = threading.Lock()

        os.makedirs(AUDIT_DIR, exist_ok=True)
        log_file = os.path.join(
            AUDIT_DIR,
            f"scan_{self.scan_id}_{self._safe(target)}.jsonl"
        )
        self.log_file = log_file
        self._fh      = open(log_file, "a")

    def _safe(self, s: str) -> str:
        return s.replace("https://","").replace("http://","").split("/")[0][:20].replace(".", "_")

    def _write(self, event: str, data: dict):
        entry = {
            "scan_id"  : self.scan_id,
            "event"    : event,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "elapsed"  : round(time.time() - self.start_ts, 2),
            "data"     : data,
        }
        with self._lock:
            self._fh.write(json.dumps(entry) + "\n")
            self._fh.flush()

    # ── Scan lifecycle ───────────────────────────────────────────────
    def start_scan(self):
        self._write("scan_start", {
            "target"  : self.target,
            "scan_id" : self.scan_id,
            "version" : "5.0",
        })

    def end_scan(self, total_findings: int, confirmed: int, elapsed: float):
        self._write("scan_end", {
            "total_findings": total_findings,
            "confirmed"     : confirmed,
            "elapsed_sec"   : round(elapsed, 1),
        })
        self._fh.close()

    # ── Step tracking ────────────────────────────────────────────────
    def log_step_start(self, step_name: str):
        self._write("step_start", {"step": step_name})

    def log_step_end(self, step_name: str, status: str, error: str = ""):
        self._write("step_end", {
            "step"  : step_name,
            "status": status,
            "error" : error,
        })

    # ── Command logging ───────────────────────────────────────────────
    def log_command(self, cmd: str, tool: str = ""):
        # Hash the command for privacy (don't log full paths)
        cmd_hash = hashlib.md5(cmd.encode()).hexdigest()[:8]
        self._write("command", {
            "tool"    : tool,
            "cmd_hash": cmd_hash,
            "cmd_len" : len(cmd),
        })

    # ── Finding logging ───────────────────────────────────────────────
    def log_finding(self, finding: dict):
        self._write("finding", {
            "type"      : finding.get("type"),
            "severity"  : finding.get("severity"),
            "url"       : finding.get("url", "")[:100],
            "status"    : finding.get("status"),
            "confidence": finding.get("confidence"),
            "tool"      : finding.get("tool"),
        })

    # ── FP tracking ──────────────────────────────────────────────────
    def log_fp_caught(self, vuln_type: str, url: str, reasons: list):
        self._write("false_positive_caught", {
            "vuln_type": vuln_type,
            "url"      : url[:100],
            "reasons"  : reasons[:3],
        })

    # ── Report ────────────────────────────────────────────────────────
    def get_summary(self) -> dict:
        """Read audit log and return summary stats."""
        if not os.path.isfile(self.log_file):
            return {}
        events = {"scan_start":0,"scan_end":0,"step_start":0,
                  "finding":0,"false_positive_caught":0,"command":0}
        try:
            with open(self.log_file) as f:
                for line in f:
                    entry = json.loads(line)
                    ev = entry.get("event","")
                    if ev in events:
                        events[ev] += 1
        except Exception:
            pass
        return {"scan_id": self.scan_id, "log_file": self.log_file, **events}
