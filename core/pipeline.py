#!/usr/bin/env python3
# core/pipeline.py — v3.0 Pipeline with parallel execution + all bug fixes

import os, time, json, subprocess, threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.utils               import get_prefix, ensure_dir, count_lines, FormatFixer
from core.rate_bypass         import RateBypass
from core.timeout_manager     import TimeoutManager
from core.pipeline_cfg_patch  import CfgShim
from ai.observer              import M7Observer
from ai.pipeline_controller  import PipelineController

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
from modules.step16_github     import GitHubDorkStep
from modules.step17_cloud      import CloudEnumStep
from modules.step18_ssti       import SSTIStep
from modules.step19_jwt        import JWTStep
from modules.step20_graphql    import GraphQLStep
from modules.step21_host_header import HostHeaderStep
from modules.step22_idor        import IDORStep
from modules.step23_xxe         import XXEStep
from modules.step24_smuggling   import SmugglingStep
from modules.report             import ReportGenerator

# ── Mode definitions ─────────────────────────────────────────────────
QUICK_STEPS   = ["subdomain","dns","probe","nuclei","xss","takeover","github","idor"]
DEEP_STEPS    = ["subdomain","dns","probe","ports","crawl","nuclei","xss",
                 "sqli","cors","lfi","ssrf","redirect","takeover","screenshot",
                 "wpscan","github","cloud","ssti","jwt","graphql","host_header",
                 "idor","xxe","smuggling"]
STEALTH_STEPS = DEEP_STEPS

# Steps that can run in parallel (don't depend on each other)
PARALLEL_GROUPS = [
    ["xss","cors","redirect","host_header"],   # URL-based tests
    ["sqli","lfi","ssrf","ssti"],              # param-based tests
    ["github","cloud"],                         # passive intel
]

class Pipeline:
    def __init__(self, target, args, tor, oob, notifier, log, scope_list=None):
        self.target     = target.strip()
        self.args       = args
        self.tor        = tor
        self.oob        = oob
        self.notifier   = notifier
        self.log        = log
        self.scope_list = scope_list or []
        self.findings   = []
        self._findings_lock = threading.Lock()
        self._seen_findings = set()

        self.bypass  = RateBypass(
            min_delay=3.0 if args.stealth else 0.3,
            max_delay=8.0 if args.stealth else 1.5
        )
        self.tmgr = TimeoutManager()
        if args.stealth:
            self.tmgr.set_stealth()
        elif args.quick:
            self.tmgr.set_fast()

        self.prefix   = get_prefix(self.target)
        self.start_t  = time.time()
        self.cfg      = CfgShim(args)
        self.observer = M7Observer(self)
        self.ceo      = PipelineController(self)

        # Auth headers from CLI
        self.auth_headers = {}
        if getattr(args, 'cookie', None):
            self.auth_headers["Cookie"] = args.cookie
        if getattr(args, 'headers', None) and os.path.isfile(args.headers):
            with open(args.headers) as f:
                for line in f:
                    if ':' in line:
                        k,_,v = line.partition(':')
                        self.auth_headers[k.strip()] = v.strip()

        # Output dir
        base = getattr(args,'output',None) or "results"
        ts   = time.strftime("%Y%m%d_%H%M%S")
        self.out = os.path.join(base, f"{self.prefix}_{ts}")
        ensure_dir(self.out)

        # File map
        p = self.prefix
        self.files = {
            "raw_input"        : os.path.join(self.out, f"{p}_raw_input.txt"),
            "subdomains"       : os.path.join(self.out, f"{p}_subdomains.txt"),
            "resolved"         : os.path.join(self.out, f"{p}_resolved.txt"),
            "live_hosts"       : os.path.join(self.out, f"{p}_live_hosts.txt"),
            "open_ports"       : os.path.join(self.out, f"{p}_open_ports.txt"),
            "urls"             : os.path.join(self.out, f"{p}_urls.txt"),
            "js_files"         : os.path.join(self.out, f"{p}_js_files.txt"),
            "js_secrets"       : os.path.join(self.out, f"{p}_js_secrets.txt"),
            "params"           : os.path.join(self.out, f"{p}_params.txt"),
            "nuclei_results"   : os.path.join(self.out, f"{p}_nuclei.txt"),
            "xss_results"      : os.path.join(self.out, f"{p}_xss.txt"),
            "sqli_params"      : os.path.join(self.out, f"{p}_sqli_params.txt"),
            "sqli_results"     : os.path.join(self.out, f"{p}_sqli_confirmed.txt"),
            "cors_results"     : os.path.join(self.out, f"{p}_cors.txt"),
            "lfi_results"      : os.path.join(self.out, f"{p}_lfi.txt"),
            "ssrf_params"      : os.path.join(self.out, f"{p}_ssrf.txt"),
            "redirect_results" : os.path.join(self.out, f"{p}_redirect.txt"),
            "takeover_results" : os.path.join(self.out, f"{p}_takeover.txt"),
            "screenshots_dir"  : os.path.join(self.out, "screenshots"),
            "wpscan_dir"       : os.path.join(self.out, "wpscan"),
            "wayback_urls"     : os.path.join(self.out, f"{p}_wayback.txt"),
            "gau_urls"         : os.path.join(self.out, f"{p}_gau.txt"),
            "dns_records"      : os.path.join(self.out, f"{p}_dns.txt"),
            "github_results"   : os.path.join(self.out, f"{p}_github.txt"),
            "cloud_results"    : os.path.join(self.out, f"{p}_cloud.txt"),
            "ssti_results"     : os.path.join(self.out, f"{p}_ssti.txt"),
            "jwt_results"      : os.path.join(self.out, f"{p}_jwt.txt"),
            "graphql_results"  : os.path.join(self.out, f"{p}_graphql.txt"),
            "host_header_results": os.path.join(self.out, f"{p}_host_header.txt"),
            "fmt_domain"       : os.path.join(self.out, f"{p}_fmt_domain.txt"),
            "fmt_url"          : os.path.join(self.out, f"{p}_fmt_url.txt"),
            "fmt_host"         : os.path.join(self.out, f"{p}_fmt_host.txt"),
        }

        with open(self.files["raw_input"], "w") as f:
            f.write(self.target + "\n")

        self.steps_to_run = self._resolve_steps()
        self.log.set_steps(len(self.steps_to_run) + 1)

    def _resolve_steps(self):
        a = self.args
        if a.quick:
            return QUICK_STEPS
        elif a.deep or a.stealth or a.continuous:
            return DEEP_STEPS
        elif a.custom:
            custom = [s for s in DEEP_STEPS if getattr(a, s, False)]
            return custom if custom else QUICK_STEPS
        return QUICK_STEPS

    def run(self) -> str:
        self.log.info(f"Output : {self.out}")
        self.log.info(f"Steps  : {' → '.join(self.steps_to_run)}")
        self.log.info(f"Tor    : {'ON' if self.tor else 'OFF'}")
        self.log.info(f"OOB    : {self.oob.server if self.oob else 'OFF'}")
        print()

        if self.notifier:
            self.notifier.send_scan_start(self.target)

        self._save_state()
        completed = self._load_completed()

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
            "github"     : GitHubDorkStep,
            "cloud"      : CloudEnumStep,
            "ssti"       : SSTIStep,
            "jwt"        : JWTStep,
            "graphql"    : GraphQLStep,
            "host_header": HostHeaderStep,
            "idor"       : IDORStep,
            "xxe"        : XXEStep,
            "smuggling"  : SmugglingStep,
        }

        # Sequential recon steps first
        recon_steps = ["subdomain","dns","probe","ports","crawl"]
        vuln_steps  = [s for s in self.steps_to_run if s not in recon_steps]

        for step_name in self.steps_to_run:
            if step_name not in recon_steps:
                continue
            if self.args.resume and step_name in completed:
                self.log.warn(f"Skipping (done): {step_name}")
                self.log._step_current += 1
                continue
            self.log.step(step_name.upper())
            StepClass = step_map.get(step_name)
            if StepClass:
                try:
                    self.observer.step_start(step_name)
                    self.ceo.before_step(step_name)
                    StepClass(self).run()
                    self._mark_completed(step_name)
                    self._refresh_fmt_files()
                    self.observer.step_end(step_name, "success")
                    self.ceo.after_step(step_name)
                except KeyboardInterrupt:
                    self.observer.step_end(step_name, "failed", error="interrupted")
                    self.log.warn("Interrupted"); break
                except Exception as e:
                    self.observer.step_end(step_name, "failed", error=str(e))
                    self.log.error(f"Step {step_name} failed: {e}")

        # Parallel vuln scanning (from Osmedeus concept)
        vuln_steps_to_run = [s for s in vuln_steps if s in self.steps_to_run]
        if vuln_steps_to_run:
            self.log.section("PARALLEL VULNERABILITY SCANNING")
            self._run_parallel(vuln_steps_to_run, step_map, completed)

        # Report
        self.log.step("REPORT")
        report_path = ReportGenerator(self).generate()
        elapsed = time.time() - self.start_t
        self.log.pipeline_done(self.target, elapsed, report_path)

        # Check for missed critical steps
        missed = self.ceo.check_for_missed_critical_steps(self.steps_to_run)
        if missed:
            self.log.warn(f"[CEO] {len(missed)} critical steps were missed:")
            for m in missed:
                self.log.warn(f"      → {m['step']}: {m['suggestion']}")
        session_file = self.observer.save_session()
        self.log.success(f"Intelligence → {session_file}")
        self.log.info(f"Run 'sudo m7hunter --analyze' to get upgrade suggestions")

        if self.notifier:
            self.notifier.send_scan_done(self.target, len(self.findings), elapsed)

        return report_path

    def _run_parallel(self, steps, step_map, completed):
        """Run vuln steps in parallel using ThreadPoolExecutor."""
        max_workers = min(len(steps), 5)  # Max 5 parallel
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for step_name in steps:
                if self.args.resume and step_name in completed:
                    self.log.warn(f"Skipping (done): {step_name}")
                    continue
                StepClass = step_map.get(step_name)
                if StepClass:
                    self.log.info(f"  → Starting parallel: {step_name}")
                    fut = executor.submit(self._run_step_safe, StepClass, step_name)
                    futures[fut] = step_name
            for fut in as_completed(futures):
                step_name = futures[fut]
                try:
                    fut.result()
                    self._mark_completed(step_name)
                except Exception as e:
                    self.log.error(f"Parallel step {step_name} failed: {e}")

    def _run_step_safe(self, StepClass, step_name):
        try:
            self.log.step(step_name.upper())
            self.observer.step_start(step_name)
            self.ceo.before_step(step_name)
            StepClass(self).run()
            self.observer.step_end(step_name, "success")
            self.ceo.after_step(step_name)
        except Exception as e:
            self.observer.step_end(step_name, "failed", error=str(e))
            self.log.error(f"Step {step_name}: {e}")
            raise

    def _refresh_fmt_files(self):
        if os.path.isfile(self.files["subdomains"]):
            FormatFixer.fix(self.files["subdomains"], self.files["fmt_domain"], "domain")
        if os.path.isfile(self.files["live_hosts"]):
            FormatFixer.fix(self.files["live_hosts"], self.files["fmt_url"],  "url")
            FormatFixer.fix(self.files["live_hosts"], self.files["fmt_host"], "host")

    def _state_file(self):
        return os.path.join(self.out, f"{self.prefix}_state.json")

    def _save_state(self):
        with open(self._state_file(),"w") as f:
            json.dump({"target":self.target,"steps":self.steps_to_run,"completed":[],"prefix":self.prefix},f,indent=2)

    def _load_completed(self):
        sf = self._state_file()
        if os.path.isfile(sf):
            with open(sf) as f:
                return json.load(f).get("completed",[])
        return []

    def _mark_completed(self, name):
        sf = self._state_file()
        state = {}
        if os.path.isfile(sf):
            with open(sf) as f: state = json.load(f)
        state.setdefault("completed",[])
        if name not in state["completed"]:
            state["completed"].append(name)
        with open(sf,"w") as f: json.dump(state,f,indent=2)

    def shell(self, cmd: str, label: str="", use_tor: bool=False,
              append_file: str=None, timeout: int=None, tool_name: str="default") -> str:
        if label:
            self.log.info(f"  ↳ {label}")

        # Get adaptive timeout
        if timeout is None:
            timeout = self.tmgr.get(tool_name)

        if use_tor and self.tor and self.tor.is_running():
            cmd = f"proxychains4 -q {cmd}"
            self.tor.tick()

        if append_file:
            cmd = f"({cmd}) 2>/dev/null | tee -a {append_file}"
        else:
            cmd = f"({cmd}) 2>/dev/null"

        start = time.time()
        try:
            result = subprocess.run(
                cmd, shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout
            )
            elapsed = time.time() - start
            self.tmgr.record(tool_name, elapsed, False)
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start
            self.tmgr.record(tool_name, elapsed, True)
            self.log.warn(f"  ↳ Timeout ({timeout}s): {label or tool_name}")
            return ""
        except Exception as e:
            self.log.error(f"  ↳ Shell error: {e}")
            return ""

    def add_finding(self, severity, vuln_type, url, detail="", tool=""):
        # Deduplicate — pipeline-level dedup (not logger-level)
        key = f"{severity}:{vuln_type}:{url}"
        with self._findings_lock:
            if key in self._seen_findings:
                return
            self._seen_findings.add(key)

        # Log to console
        self.log.finding(severity, vuln_type, url, detail)

        entry = {
            "severity": severity,
            "type"    : vuln_type,
            "url"     : url,
            "detail"  : detail,
            "tool"    : tool,
            "time"    : time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        with self._findings_lock:
            self.findings.append(entry)

        # Observer record
        self.observer.record_finding(severity, vuln_type, url, detail, tool)

        # Notify
        if self.notifier:
            self.notifier.send_finding(severity, vuln_type, url, detail, tool)
