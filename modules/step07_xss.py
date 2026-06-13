#!/usr/bin/env python3
# modules/step07_xss.py — XSS Detection (Fixed — dalfox + kxss + DOM)
# Fix: head -50 → 500, parse all dalfox output formats, add blind XSS
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY
import os, re
from core.utils import count_lines, safe_read
from core.error_handler import get_handler

class Step07Xss:
    def __init__(self, pipeline): self.p = pipeline

    def run(self):
        p   = self.p
        urls = p.files.get("urls", "")
        par  = p.files.get("params", "")
        out  = p.files.get("xss_results", "/tmp/xss_results.txt")
        t    = p.tmgr.get

        if not os.path.isfile(urls) or count_lines(urls) == 0:
            p.log.warn("XSS: no URLs — skipping"); return

        cookie_flag = f'--cookie "{p.args.cookie}"' if getattr(p.args,"cookie",None) else ""
        header_flag = f'--header "Authorization: {p.args.authorization}"' \
                      if getattr(p.args,"authorization",None) else ""
        p.log.info("XSS: Running dalfox + kxss + DOM analysis")

        # Build parameterized URL list
        tmp_params = "/tmp/m7_xss_params.txt"
        p.shell(
            f"cat {urls} {par} 2>/dev/null | grep '=' | grep '?' "
            f"| sort -u | head -1000 > {tmp_params}",
            timeout=15
        )

        if not os.path.isfile(tmp_params) or count_lines(tmp_params) == 0:
            p.log.warn("XSS: no parameterized URLs found"); return

        param_count = count_lines(tmp_params)
        p.log.info(f"XSS: {param_count} parameterized URLs to test")

        # ── kxss — fast reflected parameter finder ────────────────────
        try:
            p.shell(
                f"cat {tmp_params} | head -500 | kxss 2>/dev/null",
                label="kxss", append_file=out, timeout=t("dalfox")
            )
        except Exception as e:
            get_handler().capture("step07_xss", e, "kxss")

        # ── dalfox pipe mode — full detection ────────────────────────
        try:
            p.shell(
                f"cat {tmp_params} | head -500 | "
                f"dalfox pipe {cookie_flag} {header_flag} "
                f"--silence --no-color --timeout 10 2>/dev/null",
                label="dalfox", append_file=out, timeout=t("dalfox")
            )
        except Exception as e:
            get_handler().capture("step07_xss", e, "dalfox")

        # ── dalfox file mode for deeper scan ─────────────────────────
        try:
            p.shell(
                f"dalfox file {tmp_params} {cookie_flag} {header_flag} "
                f"--silence --no-color --timeout 10 --worker 10 2>/dev/null",
                label="dalfox-file", append_file=out, timeout=t("dalfox")
            )
        except Exception as e:
            get_handler().capture("step07_xss", e, "dalfox_file")

        # ── DOM XSS via xss_engine ────────────────────────────────────
        try:
            from engines.xss_engine import XssEngine
            XssEngine(p).run()
        except Exception as e:
            get_handler().capture("step07_xss", e, "xss_engine")

        self._parse_results(out)

    def _parse_results(self, out):
        if not os.path.isfile(out): return
        seen = set()
        for line in safe_read(out):
            if not line: continue
            u = re.findall(r'https?://\S+', line)
            url = u[0].rstrip('",)') if u else ""
            if not url or url in seen: continue

            lo = line.lower()

            # dalfox confirmed XSS patterns
            if any(p in lo for p in [
                "poc", "[v]", "verify", "[g]", "grep", "confirmed",
                "xss found", "alert(", "prompt(", "confirm(", "dalfox"
            ]):
                self.p.add_finding(
                    "high", "XSS", url,
                    f"Confirmed XSS: {line[:120]}", "dalfox"
                )
                seen.add(url)

            # kxss reflected param
            elif any(p in lo for p in [
                "kxss", "reflected", "[+]", "parameter reflected"
            ]):
                self.p.add_finding(
                    "medium", "XSS_REFLECTED", url,
                    f"Reflected parameter: {line[:100]}", "kxss"
                )
                seen.add(url)

        if seen:
            self.p.log.success(f"XSS: {len(seen)} findings")
        else:
            self.p.log.info("XSS: 0 confirmed findings")
