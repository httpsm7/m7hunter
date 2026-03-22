#!/usr/bin/env python3
# ai/analyzer.py — M7 Analyzer
# Intelligence DB ko pad ke upgrade suggestions generate karta hai
# Yeh data future AI ko train karne ke liye bhi use hoga
#
# Run: python3 -m ai.analyzer
# Ya:  sudo m7hunter --analyze
#
# MilkyWay Intelligence | Author: Sharlix

import os
import json
import time
from datetime import datetime

OBSERVER_DB   = os.path.expanduser("~/.m7hunter/intelligence.json")
SESSIONS_DIR  = os.path.expanduser("~/.m7hunter/sessions/")
REPORT_PATH   = os.path.expanduser("~/.m7hunter/upgrade_report.json")
TRAINING_PATH = os.path.expanduser("~/.m7hunter/training_data.jsonl")

R="\033[91m"; B="\033[34m"; C="\033[96m"; Y="\033[93m"
G="\033[92m"; W="\033[97m"; DIM="\033[2m"; RST="\033[0m"; BOLD="\033[1m"


class M7Analyzer:
    """
    Sab session data ko analyze karta hai.
    Output:
      1. upgrade_report.json  — kya fix karo, kya add karo
      2. training_data.jsonl  — future AI ke liye training examples
    """

    def __init__(self):
        self.master     = {}
        self.sessions   = []
        self.report     = {}

    def run(self):
        self._print_header()
        self._load_data()

        if not self.sessions:
            print(f"{Y}[!]{RST} No scan data found yet.")
            print(f"    Run at least one scan first: {W}sudo m7hunter -u target.com --quick{RST}")
            return

        print(f"{C}[*]{RST} Loaded {len(self.sessions)} scan sessions")
        print()

        # Analysis phases
        self._analyze_tool_performance()
        self._analyze_finding_patterns()
        self._analyze_false_positives()
        self._analyze_payload_effectiveness()
        self._analyze_step_coverage()
        self._generate_upgrade_suggestions()
        self._build_training_data()
        self._save_report()
        self._print_report()

    def _load_data(self):
        """Load master DB and all session files."""
        if os.path.isfile(OBSERVER_DB):
            try:
                with open(OBSERVER_DB) as f:
                    self.master = json.load(f)
            except Exception: pass

        if not os.path.isdir(SESSIONS_DIR): return
        for fname in sorted(os.listdir(SESSIONS_DIR)):
            if not fname.endswith(".json"): continue
            try:
                with open(os.path.join(SESSIONS_DIR, fname)) as f:
                    self.sessions.append(json.load(f))
            except Exception: pass

    # ── Analysis modules ──────────────────────────────────────────

    def _analyze_tool_performance(self):
        """Kaunse tools slow hain, timeout hote hain."""
        print(f"{B}━━━ Tool Performance Analysis ━━━{RST}")
        all_health = {}

        for s in self.sessions:
            for tool, health in s.get("tool_health", {}).items():
                if tool not in all_health:
                    all_health[tool] = {"calls":0,"timeout":0,"fail":0,"total_ms":0}
                all_health[tool]["calls"]    += health.get("calls", 0)
                all_health[tool]["timeout"]  += health.get("timeout", 0)
                all_health[tool]["fail"]     += health.get("fail", 0)
                all_health[tool]["total_ms"] += health.get("total_ms", 0)

        problems = []
        for tool, h in all_health.items():
            if h["calls"] == 0: continue
            to_rate   = h["timeout"] / h["calls"]
            fail_rate = h["fail"]    / h["calls"]
            avg_ms    = h["total_ms"] // max(h["calls"], 1)

            if to_rate > 0.3:
                print(f"  {R}[TIMEOUT PROBLEM]{RST} {tool:20s} timeout rate: {to_rate:.0%}")
                problems.append({"type":"timeout","tool":tool,"rate":to_rate,"avg_ms":avg_ms})
            elif fail_rate > 0.5:
                print(f"  {Y}[FAIL PROBLEM]{RST}   {tool:20s} fail rate:    {fail_rate:.0%}")
                problems.append({"type":"fail","tool":tool,"rate":fail_rate})
            elif avg_ms > 120000:
                print(f"  {Y}[SLOW TOOL]{RST}      {tool:20s} avg time:     {avg_ms//1000}s")
                problems.append({"type":"slow","tool":tool,"avg_ms":avg_ms})
            else:
                print(f"  {G}[OK]{RST}             {tool:20s} calls: {h['calls']} | avg: {avg_ms}ms")

        self.report["tool_problems"] = problems
        print()

    def _analyze_finding_patterns(self):
        """Kaunsi vulns common hain, kahan milti hain."""
        print(f"{B}━━━ Finding Pattern Analysis ━━━{RST}")
        vuln_map   = {}   # vuln_type -> count
        tool_map   = {}   # tool -> findings count
        sev_map    = {"critical":0,"high":0,"medium":0,"low":0,"info":0}

        for s in self.sessions:
            for f in s.get("findings", []):
                if not f.get("confirmed", True): continue
                vt = f.get("vuln_type","UNKNOWN")
                t  = f.get("tool","unknown")
                sv = f.get("severity","info")
                vuln_map[vt] = vuln_map.get(vt, 0) + 1
                tool_map[t]  = tool_map.get(t, 0) + 1
                sev_map[sv]  = sev_map.get(sv, 0) + 1

        total = sum(vuln_map.values())
        print(f"  Total confirmed findings: {W}{total}{RST}")
        print()

        if vuln_map:
            print(f"  {C}Top vulnerability types:{RST}")
            for vt, cnt in sorted(vuln_map.items(), key=lambda x: x[1], reverse=True)[:8]:
                bar = "█" * min(cnt * 3, 30)
                print(f"    {G}{vt:30s}{RST} {bar} {cnt}")

        print()
        if tool_map:
            print(f"  {C}Most productive tools:{RST}")
            for tool, cnt in sorted(tool_map.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"    {W}{tool:20s}{RST} → {cnt} findings")

        self.report["finding_patterns"] = {
            "vuln_counts"   : vuln_map,
            "tool_counts"   : tool_map,
            "severity_dist" : sev_map,
            "total_findings": total,
        }
        print()

    def _analyze_false_positives(self):
        """Kaunse tools galat alerts dete hain."""
        print(f"{B}━━━ False Positive Analysis ━━━{RST}")
        fp_by_tool = {}
        fp_by_vuln = {}

        for s in self.sessions:
            for fp in s.get("false_positives", []):
                vt = fp.get("vuln_type","UNKNOWN")
                fp_by_vuln[vt] = fp_by_vuln.get(vt, 0) + 1

            # Find unconfirmed findings
            for f in s.get("findings", []):
                if not f.get("confirmed", True):
                    t  = f.get("tool","unknown")
                    fp_by_tool[t] = fp_by_tool.get(t, 0) + 1

        if fp_by_vuln:
            print(f"  {C}False positive prone vuln types:{RST}")
            for vt, cnt in sorted(fp_by_vuln.items(), key=lambda x: x[1], reverse=True):
                print(f"    {Y}{vt:30s}{RST} {cnt} FPs")
        else:
            print(f"  {G}No false positives recorded yet.{RST}")
            print(f"  {DIM}Tip: after scan, run --mark-fp to mark false positives{RST}")

        self.report["false_positives"] = {
            "by_vuln_type": fp_by_vuln,
            "by_tool"     : fp_by_tool,
        }
        print()

    def _analyze_payload_effectiveness(self):
        """Kaunse payloads kaam karte hain, kaunse waste hain."""
        print(f"{B}━━━ Payload Effectiveness ━━━{RST}")
        all_payloads = {}

        for s in self.sessions:
            for payload, stats in s.get("payload_stats", {}).items():
                if payload not in all_payloads:
                    all_payloads[payload] = {"tried":0,"worked":0}
                all_payloads[payload]["tried"]  += stats.get("tried", 0)
                all_payloads[payload]["worked"] += stats.get("worked", 0)

        top_payloads  = []
        dead_payloads = []

        for p, s in all_payloads.items():
            if s["tried"] < 3: continue
            rate = s["worked"] / s["tried"]
            if rate > 0.3:
                top_payloads.append((p, rate, s["tried"]))
            elif rate == 0 and s["tried"] > 10:
                dead_payloads.append((p, s["tried"]))

        if top_payloads:
            print(f"  {C}Most effective payloads:{RST}")
            for p, rate, tried in sorted(top_payloads, key=lambda x: x[1], reverse=True)[:5]:
                print(f"    {G}{rate:.0%}{RST} success | tried {tried}x | {W}{p[:60]}{RST}")
        else:
            print(f"  {DIM}Not enough payload data yet — run more scans{RST}")

        if dead_payloads:
            print(f"\n  {C}Payloads to remove (0% success):{RST}")
            for p, tried in dead_payloads[:3]:
                print(f"    {Y}0%{RST} in {tried} tries | {DIM}{p[:60]}{RST}")

        self.report["payload_analysis"] = {
            "top_payloads" : top_payloads[:10],
            "dead_payloads": dead_payloads[:10],
        }
        print()

    def _analyze_step_coverage(self):
        """Kaunse steps skip ho rahe hain, kaunse slow hain."""
        print(f"{B}━━━ Step Coverage Analysis ━━━{RST}")
        step_stats = {}

        for s in self.sessions:
            for step_name, step in s.get("steps", {}).items():
                if step_name not in step_stats:
                    step_stats[step_name] = {
                        "runs"          : 0,
                        "success"       : 0,
                        "failed"        : 0,
                        "total_ms"      : 0,
                        "total_output"  : 0,
                    }
                ss = step_stats[step_name]
                ss["runs"]       += 1
                ss["total_ms"]   += step.get("duration_ms") or 0
                ss["total_output"]+= step.get("output_count") or 0
                if step.get("status") == "success": ss["success"] += 1
                elif step.get("status") == "failed": ss["failed"] += 1

        productive_steps = []
        weak_steps       = []

        for step, ss in step_stats.items():
            if ss["runs"] == 0: continue
            avg_ms  = ss["total_ms"]  // max(ss["runs"], 1)
            avg_out = ss["total_output"] / ss["runs"]
            fail_r  = ss["failed"] / ss["runs"]

            if avg_out > 5 and fail_r < 0.2:
                productive_steps.append((step, avg_out, avg_ms))
            elif avg_out < 1 and ss["runs"] > 2:
                weak_steps.append((step, avg_out, ss["runs"]))

            status_color = G if fail_r < 0.2 else Y if fail_r < 0.5 else R
            print(f"  {status_color}{step:20s}{RST} runs:{ss['runs']} "
                  f"avg_output:{avg_out:.1f} avg_time:{avg_ms//1000}s "
                  f"fail:{fail_r:.0%}")

        self.report["step_coverage"] = {
            "step_stats"      : step_stats,
            "productive_steps": productive_steps,
            "weak_steps"      : weak_steps,
        }
        print()

    def _generate_upgrade_suggestions(self):
        """Sari analysis se konkrete upgrade suggestions nikalna."""
        print(f"{B}━━━ Upgrade Suggestions ━━━{RST}")
        suggestions = []

        # From tool problems
        for prob in self.report.get("tool_problems", []):
            if prob["type"] == "timeout":
                suggestions.append({
                    "priority"   : "HIGH",
                    "category"   : "performance",
                    "suggestion" : f"Increase timeout for '{prob['tool']}' — timing out {prob['rate']:.0%} of the time",
                    "action"     : f"Update TOOL_TIMEOUTS['{prob['tool']}']['default'] to {int(prob.get('avg_ms',300000)*2//1000)}s",
                })
            elif prob["type"] == "fail":
                suggestions.append({
                    "priority"   : "HIGH",
                    "category"   : "bug",
                    "suggestion" : f"'{prob['tool']}' failing {prob['rate']:.0%} — check flags/installation",
                    "action"     : f"Run: which {prob['tool']} && {prob['tool']} --version",
                })

        # From false positives
        fp_data = self.report.get("false_positives", {})
        for vt, cnt in fp_data.get("by_vuln_type", {}).items():
            if cnt >= 3:
                suggestions.append({
                    "priority"   : "MEDIUM",
                    "category"   : "accuracy",
                    "suggestion" : f"'{vt}' has {cnt} false positives — improve detection logic",
                    "action"     : f"Add response validation in step handling {vt}",
                })

        # From dead payloads
        for p, tried in self.report.get("payload_analysis", {}).get("dead_payloads", []):
            suggestions.append({
                "priority"   : "LOW",
                "category"   : "optimization",
                "suggestion" : f"Payload never worked in {tried} tries — remove it",
                "action"     : f"Remove from payload list: {p[:50]}",
            })

        # From weak steps
        for step, avg_out, runs in self.report.get("step_coverage", {}).get("weak_steps", []):
            suggestions.append({
                "priority"   : "MEDIUM",
                "category"   : "effectiveness",
                "suggestion" : f"Step '{step}' produces almost no output — needs improvement",
                "action"     : f"Review {step} logic — add fallback methods or different tools",
            })

        # General suggestions based on patterns
        fp = self.report.get("finding_patterns", {})
        vuln_counts = fp.get("vuln_counts", {})
        if not vuln_counts:
            suggestions.append({
                "priority"   : "HIGH",
                "category"   : "effectiveness",
                "suggestion" : "No confirmed findings across all scans — pipeline may have issues",
                "action"     : "Run --check to verify all tools are installed correctly",
            })

        # Print suggestions
        for i, s in enumerate(sorted(suggestions, key=lambda x: ["HIGH","MEDIUM","LOW"].index(x["priority"])), 1):
            color = R if s["priority"]=="HIGH" else Y if s["priority"]=="MEDIUM" else DIM
            print(f"  {color}[{s['priority']}]{RST} [{s['category']}] {s['suggestion']}")
            print(f"         {DIM}→ {s['action']}{RST}")
            print()

        if not suggestions:
            print(f"  {G}Tool is performing well! Keep scanning to gather more data.{RST}")

        self.report["upgrade_suggestions"] = suggestions

    def _build_training_data(self):
        """
        Future AI ke liye training data build karna.
        JSONL format — ek line = ek training example.

        Format:
        {"input": "context about scan + finding", "output": "what to do / classify"}
        """
        print(f"{B}━━━ Building AI Training Data ━━━{RST}")
        examples = []

        for s in self.sessions:
            target = s.get("target", "unknown")
            mode   = s.get("scan_mode", "unknown")

            # Example 1: Step timing patterns → timeout suggestion
            for step_name, step in s.get("steps", {}).items():
                dur = step.get("duration_ms")
                status = step.get("status","unknown")
                if dur and dur > 0:
                    examples.append({
                        "type"   : "step_performance",
                        "input"  : {
                            "step"       : step_name,
                            "duration_ms": dur,
                            "status"     : status,
                            "output_lines": step.get("output_count", 0),
                            "errors"     : step.get("errors", []),
                        },
                        "label"  : (
                            "timeout_issue" if status == "timeout" else
                            "slow"          if dur > 120000 else
                            "normal"        if status == "success" else
                            "failed"
                        ),
                    })

            # Example 2: Finding context → severity classification
            for finding in s.get("findings", []):
                examples.append({
                    "type"    : "finding_classification",
                    "input"   : {
                        "vuln_type"  : finding.get("vuln_type"),
                        "tool"       : finding.get("tool"),
                        "detail"     : finding.get("detail","")[:200],
                        "payload"    : finding.get("payload","")[:100],
                        "confirmed"  : finding.get("confirmed", True),
                    },
                    "label"   : finding.get("severity","info"),
                    "confirmed": finding.get("confirmed", True),
                })

            # Example 3: Payload attempts → effectiveness
            for payload, stats in s.get("payload_stats", {}).items():
                if stats["tried"] > 0:
                    success_rate = stats["worked"] / stats["tried"]
                    examples.append({
                        "type"   : "payload_effectiveness",
                        "input"  : {
                            "payload"     : payload[:100],
                            "tried"       : stats["tried"],
                            "worked"      : stats["worked"],
                        },
                        "label"  : (
                            "high_value"  if success_rate > 0.5 else
                            "medium_value"if success_rate > 0.1 else
                            "low_value"
                        ),
                        "success_rate": success_rate,
                    })

            # Example 4: Tool health → recommendation
            for tool, health in s.get("tool_health", {}).items():
                if health.get("calls", 0) > 0:
                    timeout_rate = health.get("timeout",0) / health["calls"]
                    examples.append({
                        "type" : "tool_health",
                        "input": {
                            "tool"        : tool,
                            "timeout_rate": timeout_rate,
                            "avg_ms"      : health.get("avg_ms", 0),
                            "fail_rate"   : health.get("fail",0) / health["calls"],
                        },
                        "label": (
                            "needs_timeout_increase" if timeout_rate > 0.3 else
                            "needs_fix"              if health.get("fail",0)/health["calls"] > 0.5 else
                            "healthy"
                        ),
                    })

        # Save as JSONL
        with open(TRAINING_PATH, "w") as f:
            for ex in examples:
                f.write(json.dumps(ex) + "\n")

        print(f"  {G}[✓]{RST} Training examples generated: {W}{len(examples)}{RST}")
        print(f"  {G}[✓]{RST} Saved to: {W}{TRAINING_PATH}{RST}")
        print(f"  {DIM}    Use this file to train/fine-tune AI on M7Hunter behavior{RST}")
        print()

        self.report["training_data"] = {
            "total_examples" : len(examples),
            "path"           : TRAINING_PATH,
            "breakdown"      : {
                "step_performance"     : sum(1 for e in examples if e["type"]=="step_performance"),
                "finding_classification": sum(1 for e in examples if e["type"]=="finding_classification"),
                "payload_effectiveness": sum(1 for e in examples if e["type"]=="payload_effectiveness"),
                "tool_health"          : sum(1 for e in examples if e["type"]=="tool_health"),
            }
        }

    def _save_report(self):
        self.report["generated_at"] = datetime.now().isoformat()
        self.report["sessions_analyzed"] = len(self.sessions)
        with open(REPORT_PATH, "w") as f:
            json.dump(self.report, f, indent=2)
        print(f"  {G}[✓]{RST} Upgrade report saved: {W}{REPORT_PATH}{RST}")

    def _print_report(self):
        print()
        print(f"{B}{'═'*60}{RST}")
        print(f"{G}  M7Hunter Intelligence Report{RST}")
        print(f"{B}{'═'*60}{RST}")
        print(f"  Sessions analyzed   : {W}{len(self.sessions)}{RST}")
        fp = self.report.get("finding_patterns", {})
        print(f"  Total findings      : {W}{fp.get('total_findings', 0)}{RST}")
        sug = self.report.get("upgrade_suggestions", [])
        high = sum(1 for s in sug if s["priority"]=="HIGH")
        print(f"  Upgrade suggestions : {W}{len(sug)}{RST} ({R}{high} HIGH priority{RST})")
        td = self.report.get("training_data", {})
        print(f"  Training examples   : {W}{td.get('total_examples', 0)}{RST}")
        print()
        print(f"  {C}Next steps:{RST}")
        print(f"  1. Fix HIGH priority suggestions above")
        print(f"  2. Run more scans to grow training data")
        print(f"  3. When 500+ examples collected, train AI model:")
        print(f"     {DIM}python3 -m ai.train --data {TRAINING_PATH}{RST}")
        print(f"{B}{'═'*60}{RST}")

    def _print_header(self):
        print(f"""
{B}  ══════════════════════════════════════════════════{RST}
{W}{BOLD}  M7Hunter — AI Intelligence Analyzer v1.0{RST}
{C}  Self-learning loop | MilkyWay Intelligence{RST}
{B}  ══════════════════════════════════════════════════{RST}
""")


if __name__ == "__main__":
    M7Analyzer().run()
