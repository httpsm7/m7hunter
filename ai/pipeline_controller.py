#!/usr/bin/env python3
# ai/pipeline_controller.py — M7 Pipeline Controller (Tool ka CEO)
# Poori pipeline ko control karta hai
# Format convert karta hai, step skip prevent karta hai, commands fix karta hai
# MilkyWay Intelligence | Author: Sharlix

import os
import re
import time
from ai.tool_knowledge import ToolCommandEngine, TOOL_KB
from ai.pattern_engine import PatternEngine, CRITICAL_STEPS

G="\033[92m"; Y="\033[93m"; R="\033[91m"; C="\033[96m"
W="\033[97m"; DIM="\033[2m"; RST="\033[0m"; BOLD="\033[1m"


class PipelineController:
    """
    M7Hunter ka CEO — tool ki poori pipeline manage karta hai.

    Responsibilities:
    1. Har step se pehle: input format check + fix
    2. Har step ke baad: output validate karo
    3. Galat command detect karo aur fix karo
    4. Critical steps miss hone se bachao
    5. Tool-specific pre/post processing karo
    6. Pattern engine ko feed karo
    """

    def __init__(self, pipeline, log=None):
        self.pipeline = pipeline
        self.log      = log or pipeline.log
        self.cmd_engine = ToolCommandEngine(log)
        self.pattern_engine = PatternEngine()
        self._step_registry = {}   # step_name -> {"start", "end", "output_count", "issues"}

    # ── Pre-step hooks ─────────────────────────────────────────────

    def before_step(self, step_name: str) -> dict:
        """
        Step se pehle call karo.
        Returns: {"proceed": bool, "warnings": list, "input_fixed": bool}
        """
        result = {"proceed": True, "warnings": [], "input_fixed": False}

        # Register step start
        self._step_registry[step_name] = {
            "start"       : time.time(),
            "end"         : None,
            "output_count": 0,
            "issues"      : [],
        }

        # Check if critical step is in correct order
        warnings = self._check_dependencies(step_name)
        result["warnings"] = warnings

        # Fix input formats for this step
        fixed = self._fix_input_format(step_name)
        result["input_fixed"] = fixed

        if warnings:
            for w in warnings:
                self.log.warn(f"[CEO] {w}")

        return result

    def after_step(self, step_name: str, output_file: str = None) -> dict:
        """
        Step ke baad call karo.
        Returns: {"output_count": int, "issues": list, "suggestions": list}
        """
        reg  = self._step_registry.get(step_name, {})
        result = {"output_count": 0, "issues": [], "suggestions": []}

        # Count output
        if output_file and os.path.isfile(output_file):
            try:
                with open(output_file) as f:
                    count = sum(1 for l in f if l.strip())
                result["output_count"] = count
                reg["output_count"]    = count
            except Exception:
                pass

        reg["end"] = time.time()

        # Validate output
        issues = self._validate_output(step_name, result["output_count"])
        result["issues"] = issues
        reg["issues"]    = issues

        if issues:
            for issue in issues:
                self.log.warn(f"[CEO] {issue}")
                result["suggestions"].append(self._get_fix_suggestion(step_name, issue))

        return result

    # ── Command validation + fix ───────────────────────────────────

    def validate_and_fix_command(self, tool: str, command: str) -> tuple:
        """
        Command check karo. Galat hai toh fix karo.
        Returns: (fixed_command, was_fixed, issue_description)
        """
        is_valid, issue, fixed = self.cmd_engine.validate_command(tool, command)

        if not is_valid:
            self.log.warn(f"[CEO] Command issue detected for {tool}:")
            self.log.warn(f"      {issue}")
            self.log.info(f"[CEO] Auto-fixed: {fixed[:100]}")
            self.pattern_engine.record_fix_worked("command_fix", tool, command, fixed)
            return fixed, True, issue

        return command, False, ""

    def get_correct_command(self, tool: str, mode: str = "default", **kwargs) -> str:
        """Get the verified correct command for a tool."""
        cmd = self.cmd_engine.get_command(tool, mode, **kwargs)
        if not cmd:
            self.log.warn(f"[CEO] Unknown tool: {tool}")
        return cmd

    # ── Format fixing ──────────────────────────────────────────────

    def _fix_input_format(self, step_name: str) -> bool:
        """
        Step ke input ko correct format mein convert karo.
        Tool-specific rules apply karo.
        """
        p = self.pipeline
        f = p.files
        fixed = False

        FORMAT_RULES = {
            # Step name -> {source_file, dest_file, format, pre_process_cmd}
            "dns": {
                "source": f.get("subdomains"),
                "dest"  : f.get("fmt_domain"),
                "format": "domain",
                "strip_cmd": "sed 's/ \\[.*//g'",  # strip dnsx [IP] suffix
            },
            "probe": {
                "source": f.get("resolved") or f.get("subdomains"),
                "dest"  : f.get("fmt_host"),
                "format": "host",
            },
            "ports": {
                "source": f.get("resolved") or f.get("subdomains"),
                "dest"  : f.get("fmt_host"),
                "format": "host",
                "extra_strip": "sed -i 's|https\\?://||g; s|/.*||; s|:.*||'",
            },
            "crawl": {
                "source": f.get("live_hosts"),
                "dest"  : f.get("fmt_url"),
                "format": "url",
            },
            "nuclei": {
                "source": f.get("live_hosts"),
                "dest"  : f.get("fmt_url"),
                "format": "url",
            },
            "xss": {
                "source": f.get("live_hosts"),
                "dest"  : f.get("fmt_url"),
                "format": "url",
            },
            "screenshot": {
                "source": f.get("live_hosts"),
                "dest"  : f.get("fmt_url"),
                "format": "url",
            },
            "takeover": {
                "source": f.get("subdomains"),
                "dest"  : f.get("fmt_domain"),
                "format": "domain",
            },
        }

        if step_name in FORMAT_RULES:
            rule   = FORMAT_RULES[step_name]
            source = rule.get("source")
            dest   = rule.get("dest")
            fmt    = rule.get("format")

            if source and dest and fmt and os.path.isfile(source):
                from core.utils import FormatFixer
                n = FormatFixer.fix(source, dest, fmt)

                # Apply extra strip if needed (e.g. for nmap)
                extra = rule.get("extra_strip")
                if extra and dest:
                    p.shell(f"{extra} {dest} 2>/dev/null")

                if n > 0:
                    fixed = True
                    self.log.info(f"[CEO] Format fixed for {step_name}: {n} entries → {fmt} format")

        return fixed

    def _check_dependencies(self, step_name: str) -> list:
        """Check if required previous steps have output."""
        p        = self.pipeline
        f        = p.files
        warnings = []

        DEPS = {
            "dns"       : [("subdomains", f.get("subdomains"))],
            "probe"     : [("resolved",   f.get("resolved"))],
            "ports"     : [("resolved",   f.get("resolved"))],
            "crawl"     : [("live_hosts", f.get("live_hosts"))],
            "nuclei"    : [("live_hosts", f.get("live_hosts"))],
            "xss"       : [("urls",       f.get("urls")),
                           ("live_hosts", f.get("live_hosts"))],
            "sqli"      : [("urls",       f.get("urls"))],
            "ssrf"      : [("urls",       f.get("urls"))],
            "takeover"  : [("subdomains", f.get("subdomains"))],
        }

        if step_name in DEPS:
            for dep_name, dep_file in DEPS[step_name]:
                if dep_file and not os.path.isfile(dep_file):
                    warnings.append(
                        f"Step '{step_name}' depends on '{dep_name}' "
                        f"but file not found: {dep_file}"
                    )
                elif dep_file and os.path.isfile(dep_file):
                    from core.utils import count_lines
                    n = count_lines(dep_file)
                    if n == 0:
                        warnings.append(
                            f"Step '{step_name}': dependency '{dep_name}' is empty — "
                            f"results may be incomplete"
                        )

        return warnings

    def _validate_output(self, step_name: str, output_count: int) -> list:
        """Output validate karo."""
        issues = []

        EXPECTED_MINIMUMS = {
            "subdomain" : 1,
            "dns"       : 1,
            "probe"     : 1,
            "crawl"     : 5,
            "nuclei"    : 0,   # 0 is fine (no vulns found)
            "xss"       : 0,
            "sqli"      : 0,
            "ssrf"      : 0,
        }

        if step_name in EXPECTED_MINIMUMS:
            minimum = EXPECTED_MINIMUMS[step_name]
            if output_count < minimum:
                issues.append(
                    f"Step '{step_name}' produced {output_count} lines "
                    f"(expected at least {minimum})"
                )

        return issues

    def _get_fix_suggestion(self, step_name: str, issue: str) -> str:
        SUGGESTIONS = {
            "subdomain": "Check subfinder/amass installation. Try: subfinder -d target.com -silent",
            "dns"      : "Check dnsx. Ensure subdomains file has content. Try: dnsx -version",
            "probe"    : "Check httpx. Ensure DNS resolved hosts. Try: httpx -l resolved.txt -silent",
            "crawl"    : "Crawl needs live_hosts. Check probe step ran successfully.",
        }
        return SUGGESTIONS.get(step_name, f"Check {step_name} step configuration")

    # ── Skip prevention ────────────────────────────────────────────

    def check_for_missed_critical_steps(self, steps_completed: list) -> list:
        """
        Scan ke baad check karo — koi critical step miss toh nahi hua?
        Returns list of missed critical steps with recommendations.
        """
        missed = []
        for step in CRITICAL_STEPS:
            if step not in steps_completed:
                kb_hint = ""
                if step in ["ssrf", "xss"] and "oob" not in " ".join(steps_completed):
                    kb_hint = " + OOB/Interactsh recommended for blind detection"
                missed.append({
                    "step"      : step,
                    "reason"    : "Critical step was not in scan pipeline",
                    "suggestion": f"Add --{step} flag or use --deep mode{kb_hint}",
                })
        return missed

    def get_step_summary(self) -> dict:
        """Full summary of all steps this session."""
        summary = {}
        for step, data in self._step_registry.items():
            elapsed = None
            if data.get("start") and data.get("end"):
                elapsed = round(data["end"] - data["start"], 1)
            summary[step] = {
                "elapsed_sec" : elapsed,
                "output_count": data.get("output_count", 0),
                "issues"      : data.get("issues", []),
            }
        return summary

    # ── Knowledge base lookups ─────────────────────────────────────

    def what_does_tool_need(self, tool: str) -> str:
        """Tool ko kya input chahiye?"""
        return self.cmd_engine.get_input_format(tool)

    def how_to_run(self, tool: str, mode: str = "default", **kwargs) -> str:
        """Tool ko correctly kaise run karo?"""
        return self.cmd_engine.get_command(tool, mode, **kwargs)

    def fix_broken_command(self, tool: str, broken_cmd: str) -> str:
        """Broken command fix karo."""
        fixed, was_fixed, issue = self.validate_and_fix_command(tool, broken_cmd)
        return fixed

    def full_tool_health_check(self) -> dict:
        """Saare tools ka health check."""
        results = {}
        for tool in self.cmd_engine.list_all_tools():
            results[tool] = self.cmd_engine.check_tool(tool)
        return results
