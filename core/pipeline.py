#!/usr/bin/env python3
# core/pipeline.py — Step-by-step pipeline orchestrator

import os
import time
import json
from core.utils      import get_prefix, ensure_dir, count_lines, FormatFixer
from core.rate_bypass import RateBypass

# ── Step imports ────────────────────────────────────────────────────
from modules.step01_subdomain  import SubdomainStep
from modules.step02_dns        import DNSStep
from modules.step03_probe      import ProbeStep
from modules.step04_ports      import PortsStep
from modules.step05_crawl      import CrawlStep
from modules.step06_nuclei     import NucleiStep
from modules.step07_xss        import XSSStep
from modules.step08_sqli       import SQLiStep
from modules.step09_cors       import CORSStep
from modules.step10_lfi        import LFIStep
from modules.step11_ssrf       import SSRFStep
from modules.step12_redirect   import RedirectStep
from modules.step13_takeover   import TakeoverStep
from modules.step14_screenshot import ScreenshotStep
from modules.step15_wpscan     import WPScanStep
from modules.report            import ReportGenerator


# ── Mode definitions ────────────────────────────────────────────────
QUICK_STEPS   = ["subdomain","dns","probe","nuclei","xss","sqli","takeover"]
DEEP_STEPS    = ["subdomain","dns","probe","ports","crawl","nuclei","xss",
                 "sqli","cors","lfi","ssrf","redirect","takeover","screenshot","wpscan"]
STEALTH_STEPS = DEEP_STEPS   # same as deep but with Tor + jitter


class Pipeline:
    def __init__(self, target: str, args, tor, log):
        self.target  = target.strip()
        self.args    = args
        self.tor     = tor
        self.log     = log
        self.bypass  = RateBypass(
            min_delay = 3.0 if args.stealth else 0.3,
            max_delay = 8.0 if args.stealth else 1.5
        )
        self.prefix  = get_prefix(self.target)
        self.start_t = time.time()
        self.findings= []

        # ── Output directory ────────────────────────────────────────
        base = args.output or "results"
        ts   = time.strftime("%Y%m%d_%H%M%S")
        self.out = os.path.join(base, f"{self.prefix}_{ts}")
        ensure_dir(self.out)

        # ── Shared file paths (passed between steps) ────────────────
        p = self.prefix
        self.files = {
            # raw inputs
            "raw_input"       : os.path.join(self.out, f"{p}_raw_input.txt"),
            # step outputs
            "subdomains"      : os.path.join(self.out, f"{p}_subdomains.txt"),
            "resolved"        : os.path.join(self.out, f"{p}_resolved.txt"),
            "live_hosts"      : os.path.join(self.out, f"{p}_live_hosts.txt"),
            "open_ports"      : os.path.join(self.out, f"{p}_open_ports.txt"),
            "urls"            : os.path.join(self.out, f"{p}_urls.txt"),
            "js_files"        : os.path.join(self.out, f"{p}_js_files.txt"),
            "js_secrets"      : os.path.join(self.out, f"{p}_js_secrets.txt"),
            "params"          : os.path.join(self.out, f"{p}_params.txt"),
            "nuclei_results"  : os.path.join(self.out, f"{p}_nuclei.txt"),
            "xss_results"     : os.path.join(self.out, f"{p}_xss.txt"),
            "sqli_params"     : os.path.join(self.out, f"{p}_sqli_params.txt"),
            "cors_results"    : os.path.join(self.out, f"{p}_cors.txt"),
            "lfi_results"     : os.path.join(self.out, f"{p}_lfi.txt"),
            "ssrf_params"     : os.path.join(self.out, f"{p}_ssrf.txt"),
            "redirect_results": os.path.join(self.out, f"{p}_redirect.txt"),
            "takeover_results": os.path.join(self.out, f"{p}_takeover.txt"),
            "screenshots_dir" : os.path.join(self.out, "screenshots"),
            "wpscan_dir"      : os.path.join(self.out, "wpscan"),
            "wayback_urls"    : os.path.join(self.out, f"{p}_wayback.txt"),
            "gau_urls"        : os.path.join(self.out, f"{p}_gau.txt"),
            "dns_records"     : os.path.join(self.out, f"{p}_dns.txt"),
            # formatted variants (auto-fixed per tool)
            "fmt_domain"      : os.path.join(self.out, f"{p}_fmt_domain.txt"),
            "fmt_url"         : os.path.join(self.out, f"{p}_fmt_url.txt"),
            "fmt_host"        : os.path.join(self.out, f"{p}_fmt_host.txt"),
        }

        # Write raw input seed
        with open(self.files["raw_input"], "w") as f:
            f.write(self.target + "\n")

        # ── Determine which steps to run ────────────────────────────
        self.steps_to_run = self._resolve_steps()
        self.log.set_steps(len(self.steps_to_run) + 1)  # +1 for report

    # ─────────────────────────────────────────────────────────────────
    def _resolve_steps(self) -> list:
        a = self.args
        if a.quick:
            return QUICK_STEPS
        elif a.deep or a.stealth:
            return DEEP_STEPS
        elif a.custom:
            custom = []
            for s in DEEP_STEPS:
                attr = s.replace("-", "_")
                if getattr(a, attr, False):
                    custom.append(s)
            return custom if custom else QUICK_STEPS
        else:
            # Default: quick if no mode given
            return QUICK_STEPS

    # ─────────────────────────────────────────────────────────────────
    def run(self) -> str:
        self.log.info(f"Output dir  : {self.out}")
        self.log.info(f"File prefix : {self.prefix}_*")
        self.log.info(f"Steps       : {' → '.join(self.steps_to_run)}")
        self.log.info(f"Tor         : {'ON' if self.tor else 'OFF'}")
        print()

        # Save state for resume
        self._save_state()

        step_map = {
            "subdomain"  : SubdomainStep,
            "dns"        : DNSStep,
            "probe"      : ProbeStep,
            "ports"      : PortsStep,
            "crawl"      : CrawlStep,
            "nuclei"     : NucleiStep,
            "xss"        : XSSStep,
            "sqli"       : SQLiStep,
            "cors"       : CORSStep,
            "lfi"        : LFIStep,
            "ssrf"       : SSRFStep,
            "redirect"   : RedirectStep,
            "takeover"   : TakeoverStep,
            "screenshot" : ScreenshotStep,
            "wpscan"     : WPScanStep,
        }

        completed = self._load_completed()

        for step_name in self.steps_to_run:
            if self.args.resume and step_name in completed:
                self.log.warn(f"Skipping (already done): {step_name}")
                self._step_current_inc()
                continue

            self.log.step(step_name.upper())

            StepClass = step_map.get(step_name)
            if not StepClass:
                self.log.warn(f"Unknown step: {step_name}")
                continue

            try:
                step = StepClass(self)
                step.run()
                self._mark_completed(step_name)
                # Auto-generate format-fixed files after each step
                self._refresh_fmt_files()
            except KeyboardInterrupt:
                self.log.warn("Interrupted — saving progress...")
                break
            except Exception as e:
                self.log.error(f"Step {step_name} failed: {e}")
                continue

        # ── Generate report ─────────────────────────────────────────
        self.log.step("REPORT GENERATION")
        report_path = ReportGenerator(self).generate()

        elapsed = time.time() - self.start_t
        self.log.pipeline_done(self.target, elapsed, report_path)
        return report_path

    # ─────────────────────────────────────────────────────────────────
    #  FORMAT FIXER — runs after every step to keep fmt_* files fresh
    # ─────────────────────────────────────────────────────────────────
    def _refresh_fmt_files(self):
        """
        Regenerate format-fixed variants from live_hosts / subdomains.
        Tools will call these instead of the raw files.
        """
        # domain-only from subdomains
        if os.path.isfile(self.files["subdomains"]):
            FormatFixer.fix(self.files["subdomains"], self.files["fmt_domain"], "domain")

        # url (https://) from live_hosts
        if os.path.isfile(self.files["live_hosts"]):
            FormatFixer.fix(self.files["live_hosts"], self.files["fmt_url"],  "url")
            FormatFixer.fix(self.files["live_hosts"], self.files["fmt_host"], "host")

    # ─────────────────────────────────────────────────────────────────
    #  STATE / RESUME
    # ─────────────────────────────────────────────────────────────────
    def _state_file(self):
        return os.path.join(self.out, f"{self.prefix}_state.json")

    def _save_state(self):
        state = {
            "target": self.target,
            "steps" : self.steps_to_run,
            "completed": [],
            "prefix": self.prefix,
        }
        with open(self._state_file(), "w") as f:
            json.dump(state, f, indent=2)

    def _load_completed(self) -> list:
        sf = self._state_file()
        if os.path.isfile(sf):
            with open(sf) as f:
                return json.load(f).get("completed", [])
        return []

    def _mark_completed(self, step_name):
        sf = self._state_file()
        state = {}
        if os.path.isfile(sf):
            with open(sf) as f:
                state = json.load(f)
        state.setdefault("completed", [])
        if step_name not in state["completed"]:
            state["completed"].append(step_name)
        with open(sf, "w") as f:
            json.dump(state, f, indent=2)

    def _step_current_inc(self):
        self.log._step_current += 1

    # ─────────────────────────────────────────────────────────────────
    #  SHELL HELPER
    # ─────────────────────────────────────────────────────────────────
    def shell(self, cmd: str, label: str = "", use_tor: bool = False,
              append_file: str = None, timeout: int = 600) -> str:
        import subprocess
        if label:
            self.log.info(f"  ↳ {label}")

        if use_tor and self.tor and self.tor.is_running():
            cmd = f"proxychains4 -q {cmd}"
            self.tor.tick()

        if append_file:
            cmd = f"({cmd}) 2>/dev/null | tee -a {append_file}"
        else:
            cmd = f"({cmd}) 2>/dev/null"

        try:
            result = subprocess.run(
                cmd, shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout
            )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            self.log.warn(f"  ↳ Timeout: {label}")
            return ""
        except Exception as e:
            self.log.error(f"  ↳ Shell error: {e}")
            return ""

    def add_finding(self, severity: str, vuln_type: str, url: str,
                    detail: str = "", tool: str = ""):
        self.log.finding(severity, vuln_type, url, detail)
        self.findings.append({
            "severity" : severity,
            "type"     : vuln_type,
            "url"      : url,
            "detail"   : detail,
            "tool"     : tool,
            "time"     : time.strftime("%Y-%m-%d %H:%M:%S"),
        })
