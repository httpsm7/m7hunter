#!/usr/bin/env python3
# ai/pattern_engine.py — M7 Pattern Learning Engine
# Tools ki timing patterns, miss steps, forgotten checks track karta hai
# Har scan ke baad patterns update hote hain
# MilkyWay Intelligence | Author: Sharlix

import os
import json
import time
import statistics
from datetime import datetime
from typing import Optional

PATTERNS_FILE = os.path.expanduser("~/.m7hunter/patterns.json")

# Steps jo kabhi miss nahi hone chahiye (critical path)
CRITICAL_STEPS = [
    "subdomain", "dns", "probe",          # recon core
    "nuclei",                              # primary vuln scanner
    "ssrf", "xss", "sqli",               # top bug bounty vulns
    "takeover",                            # easy critical
]

# Patterns that indicate a step was effectively skipped
EMPTY_OUTPUT_THRESHOLD = 2   # less than 2 lines = probably didn't work

# Tool pairs that should always run together
TOOL_PAIRS = [
    ("subdomain", "dns"),      # subdomains always need DNS resolution
    ("probe", "crawl"),        # live hosts need crawling
    ("crawl", "nuclei"),       # crawl output feeds nuclei
    ("ssrf", "oob_check"),     # SSRF needs OOB verification
]


class PatternEngine:
    """
    M7Hunter ka learning brain.

    Kya karta hai:
    1. Har tool ki timing patterns track karta hai
    2. Detect karta hai kaunse steps effectively miss ho gaye
    3. Yaad rakhta hai kya bhula gaya (common misses)
    4. Patterns ke base pe suggestions deta hai
    5. Next scan ke liye recommendations generate karta hai
    """

    def __init__(self):
        self.patterns = self._load()

    def _load(self) -> dict:
        if os.path.isfile(PATTERNS_FILE):
            try:
                with open(PATTERNS_FILE) as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "tool_timings"     : {},   # tool -> [timing_ms list]
            "step_outputs"     : {},   # step -> [output_count list]
            "missed_steps"     : {},   # step -> miss_count
            "forgotten_checks" : [],   # list of checks brain forgot
            "common_misses"    : {},   # pattern -> count of times missed
            "scan_profiles"    : [],   # last 10 scan summaries
            "learned_fixes"    : [],   # auto-fixes that worked
            "total_scans"      : 0,
        }

    def _save(self):
        os.makedirs(os.path.dirname(PATTERNS_FILE), exist_ok=True)
        with open(PATTERNS_FILE, "w") as f:
            json.dump(self.patterns, f, indent=2)

    # ── Learn from scan ───────────────────────────────────────────

    def learn_from_session(self, session_data: dict):
        """
        Ek completed scan session se seekho.
        Pipeline ke baad call karo.
        """
        steps      = session_data.get("steps", {})
        tool_health= session_data.get("tool_health", {})
        findings   = session_data.get("findings", [])
        mode       = session_data.get("scan_mode", "unknown")

        # 1. Tool timing patterns
        for tool, health in tool_health.items():
            avg_ms = health.get("avg_ms", 0)
            if avg_ms > 0:
                if tool not in self.patterns["tool_timings"]:
                    self.patterns["tool_timings"][tool] = []
                self.patterns["tool_timings"][tool].append(avg_ms)
                # Keep last 20
                self.patterns["tool_timings"][tool] = \
                    self.patterns["tool_timings"][tool][-20:]

        # 2. Step output tracking
        for step_name, step in steps.items():
            out_count = step.get("output_count", 0)
            if step_name not in self.patterns["step_outputs"]:
                self.patterns["step_outputs"][step_name] = []
            self.patterns["step_outputs"][step_name].append(out_count)
            self.patterns["step_outputs"][step_name] = \
                self.patterns["step_outputs"][step_name][-20:]

        # 3. Detect missed critical steps
        steps_run = list(steps.keys())
        for critical in CRITICAL_STEPS:
            if critical not in steps_run:
                self.patterns["missed_steps"][critical] = \
                    self.patterns["missed_steps"].get(critical, 0) + 1

        # 4. Detect effectively empty steps (step ran but produced nothing)
        for step_name, step in steps.items():
            if (step.get("status") == "success" and
                    step.get("output_count", 0) < EMPTY_OUTPUT_THRESHOLD):
                key = f"{step_name}_empty"
                self.patterns["common_misses"][key] = \
                    self.patterns["common_misses"].get(key, 0) + 1

        # 5. Detect forgotten checks
        self._detect_forgotten_checks(steps_run, findings, session_data)

        # 6. Scan profile
        self.patterns["scan_profiles"].append({
            "timestamp"  : datetime.now().isoformat(),
            "mode"       : mode,
            "steps_run"  : steps_run,
            "findings"   : len(findings),
            "target"     : session_data.get("target", "?"),
        })
        self.patterns["scan_profiles"] = self.patterns["scan_profiles"][-10:]
        self.patterns["total_scans"]  += 1

        self._save()

    def _detect_forgotten_checks(self, steps_run: list, findings: list, session: dict):
        """Detect checks that should have been done but weren't."""
        forgotten = []

        # SSRF ran but no OOB configured
        if "ssrf" in steps_run and not session.get("meta", {}).get("oob_used"):
            forgotten.append({
                "check"  : "oob_for_ssrf",
                "message": "SSRF step ran without OOB/Interactsh — blind SSRF cannot be detected",
                "fix"    : "Configure Interactsh: sudo m7hunter -u target --ssrf (OOB auto-configured)",
            })

        # Ports ran but no nuclei on open ports
        if "ports" in steps_run and "nuclei" not in steps_run:
            forgotten.append({
                "check"  : "nuclei_after_ports",
                "message": "Port scan ran but Nuclei was not run — open services not checked for CVEs",
                "fix"    : "Add --nuclei flag or use --deep mode",
            })

        # XSS ran but no blind XSS
        if "xss" in steps_run:
            xss_findings = [f for f in findings if "XSS" in f.get("vuln_type","")]
            blind_xss    = [f for f in xss_findings if "BLIND" in f.get("vuln_type","")]
            if xss_findings and not blind_xss and not session.get("meta",{}).get("oob_used"):
                forgotten.append({
                    "check"  : "blind_xss_oob",
                    "message": "XSS step ran but no OOB for blind XSS detection",
                    "fix"    : "Setup Interactsh for OOB blind XSS detection",
                })

        # GitHub dork not done
        if "github" not in steps_run:
            forgotten.append({
                "check"  : "github_dork",
                "message": "GitHub dorking was skipped — possible leaked secrets/keys not checked",
                "fix"    : "Use --deep mode or add --github flag",
            })

        # Cloud assets not checked
        if "cloud" not in steps_run:
            forgotten.append({
                "check"  : "cloud_enum",
                "message": "Cloud asset enumeration skipped — S3/GCP/Azure buckets not checked",
                "fix"    : "Use --deep mode or add --cloud flag",
            })

        # JWT not checked on live hosts
        if "jwt" not in steps_run:
            forgotten.append({
                "check"  : "jwt_analysis",
                "message": "JWT analysis skipped — token vulnerabilities not checked",
                "fix"    : "Add --jwt flag",
            })

        # Store forgotten checks (deduplicated)
        existing_checks = {f["check"] for f in self.patterns["forgotten_checks"]}
        for f in forgotten:
            if f["check"] not in existing_checks:
                f["seen_count"] = 1
                self.patterns["forgotten_checks"].append(f)
            else:
                for ef in self.patterns["forgotten_checks"]:
                    if ef["check"] == f["check"]:
                        ef["seen_count"] = ef.get("seen_count", 1) + 1

    # ── Analysis ──────────────────────────────────────────────────

    def get_slow_tools(self, threshold_ms: int = 60000) -> list:
        """Tools jo consistently slow hain."""
        slow = []
        for tool, timings in self.patterns["tool_timings"].items():
            if len(timings) < 2: continue
            avg = statistics.mean(timings)
            if avg > threshold_ms:
                slow.append({
                    "tool"   : tool,
                    "avg_ms" : int(avg),
                    "samples": len(timings),
                    "trend"  : "increasing" if timings[-1] > timings[0] else "stable",
                })
        return sorted(slow, key=lambda x: x["avg_ms"], reverse=True)

    def get_timeout_tools(self, sessions_dir: str = None) -> list:
        """Tools jo timeout hote hain baar baar."""
        problematic = []
        for tool, timings in self.patterns["tool_timings"].items():
            if not timings: continue
            # High variance = often timing out
            if len(timings) >= 3:
                variance = statistics.variance(timings)
                if variance > 1_000_000_000:  # 1 billion ms^2 = very inconsistent
                    problematic.append({
                        "tool"    : tool,
                        "variance": int(variance),
                        "reason"  : "High timing variance suggests frequent timeouts",
                    })
        return problematic

    def get_weak_steps(self) -> list:
        """Steps jo consistently empty output dete hain."""
        weak = []
        for step, outputs in self.patterns["step_outputs"].items():
            if len(outputs) < 2: continue
            avg_output = statistics.mean(outputs)
            if avg_output < EMPTY_OUTPUT_THRESHOLD:
                weak.append({
                    "step"      : step,
                    "avg_output": avg_output,
                    "samples"   : len(outputs),
                })
        return weak

    def get_missed_steps(self) -> list:
        """Steps jo scan mein miss hote hain baar baar."""
        return sorted(
            [{"step": s, "miss_count": c}
             for s, c in self.patterns["missed_steps"].items()
             if c >= 2],
            key=lambda x: x["miss_count"], reverse=True
        )

    def get_forgotten_checks(self) -> list:
        """Checks jo brain bhool jaata hai baar baar."""
        return sorted(
            self.patterns["forgotten_checks"],
            key=lambda x: x.get("seen_count", 1), reverse=True
        )

    def get_common_misses(self) -> list:
        """Steps jo run toh hue lekin effectively kaam nahi kiya."""
        return sorted(
            [{"pattern": p, "count": c}
             for p, c in self.patterns["common_misses"].items()
             if c >= 2],
            key=lambda x: x["count"], reverse=True
        )

    def get_full_report(self) -> dict:
        """Complete pattern report."""
        return {
            "slow_tools"      : self.get_slow_tools(),
            "timeout_prone"   : self.get_timeout_tools(),
            "weak_steps"      : self.get_weak_steps(),
            "missed_steps"    : self.get_missed_steps(),
            "forgotten_checks": self.get_forgotten_checks(),
            "common_misses"   : self.get_common_misses(),
            "total_scans"     : self.patterns["total_scans"],
            "generated_at"    : datetime.now().isoformat(),
        }

    def record_fix_worked(self, fix_type: str, tool: str, original_cmd: str, fixed_cmd: str):
        """Record karo ki ek auto-fix kaam aaya — future mein prioritize karo."""
        self.patterns["learned_fixes"].append({
            "fix_type"   : fix_type,
            "tool"       : tool,
            "original"   : original_cmd[:100],
            "fixed"      : fixed_cmd[:100],
            "timestamp"  : datetime.now().isoformat(),
        })
        self.patterns["learned_fixes"] = self.patterns["learned_fixes"][-50:]
        self._save()
