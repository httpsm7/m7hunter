#!/usr/bin/env python3
# modules/step07_xss.py — XSS Detection (dalfox + kxss + xss_engine)
# MilkyWay Intelligence | Author: Sharlix
import os, re
from core.utils import count_lines, safe_read
from engines.xss_engine import XssEngine

class Step07Xss:
    def __init__(self, pipeline): self.p = pipeline
    def run(self):
        p    = self.p
        urls = p.files["urls"]
        par  = p.files["params"]
        out  = p.files["xss_results"]
        t    = p.tmgr.get

        if not os.path.isfile(urls) or count_lines(urls) == 0:
            p.log.warn("XSS: no URLs — skipping"); return

        cookie_flag = f'--cookie "{p.args.cookie}"' if getattr(p.args,"cookie",None) else ""
        p.log.info("XSS: dalfox + kxss + M7 XssEngine")

        # Filter parameterized URLs
        p.shell(f"cat {urls} {par} 2>/dev/null | grep '=' | grep '?' | sort -u > /tmp/xss_params.txt", timeout=10)

        # kxss — fast reflected finder
        p.shell(f"cat /tmp/xss_params.txt | head -200 | kxss 2>/dev/null",
                label="kxss", append_file=out, timeout=t("dalfox"))

        # dalfox pipe mode
        p.shell(
            f"cat /tmp/xss_params.txt | head -50 | "
            f"dalfox pipe {cookie_flag} --silence --no-color 2>/dev/null "
            f"| grep -E '(POC|XSS|Confirmed)'",
            label="dalfox pipe", tool_name="dalfox",
            append_file=out, timeout=t("dalfox"))

        # M7 XssEngine — DOM XSS + Blind XSS
        try:
            engine = XssEngine(p)
            engine.run()
        except Exception as e:
            p.log.warn(f"XssEngine: {e}")

        self._parse_results(out)
        p.log.success(f"XSS: {count_lines(out)} candidates")

    def _parse_results(self, out):
        if not os.path.isfile(out): return
        with open(out) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                urls = re.findall(r'https?://\S+', line)
                if not urls: continue
                if "POC" in line or "Confirmed" in line:
                    self.p.add_finding("high","XSS",urls[0],line[:100],"dalfox")
                elif "kxss" in line.lower() or "reflected" in line.lower():
                    self.p.add_finding("medium","XSS_CANDIDATE",urls[0],line[:80],"kxss")
