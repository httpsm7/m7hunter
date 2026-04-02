#!/usr/bin/env python3
# modules/step07_xss.py — XSS Detection (dalfox + kxss)
# MilkyWay Intelligence | Author: Sharlix

import os, re
from core.utils import count_lines, safe_read


class Step07Xss:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p    = self.p
        urls = p.files["urls"]
        par  = p.files["params"]
        out  = p.files["xss_results"]
        t    = p.tmgr.get

        if not os.path.isfile(urls) or count_lines(urls) == 0:
            p.log.warn("XSS: no URLs — skipping"); return

        cookie_flag = f'--cookie "{p.args.cookie}"' if getattr(p.args,"cookie",None) else ""
        p.log.info("XSS scanning (dalfox + kxss)")

        # Filter URLs with params
        p.shell(
            f"cat {urls} {par} 2>/dev/null | grep '=' | grep '?' | sort -u > /tmp/xss_params.txt",
            timeout=10
        )

        if count_lines("/tmp/xss_params.txt") == 0:
            p.log.warn("XSS: no parameterized URLs found"); return

        # kxss — fast reflected XSS finder
        p.shell(
            f"cat /tmp/xss_params.txt | head -200 | kxss 2>/dev/null",
            label="kxss", append_file=out, timeout=t("dalfox")
        )

        # dalfox — deep XSS
        live = safe_read(p.files.get("fmt_url",""))[:5]
        for host in live:
            p.shell(
                f"dalfox url {host} {cookie_flag} "
                f"--silence --skip-bav --no-color 2>/dev/null | grep -E '(POC|XSS|Confirmed)'",
                label=f"dalfox {host[:40]}", tool_name="dalfox",
                append_file=out, timeout=t("dalfox")
            )

        # dalfox pipe mode on param list
        p.shell(
            f"cat /tmp/xss_params.txt | head -50 | "
            f"dalfox pipe {cookie_flag} --silence --no-color 2>/dev/null "
            f"| grep -E '(POC|XSS|Confirmed)'",
            label="dalfox pipe", tool_name="dalfox",
            append_file=out, timeout=t("dalfox")
        )

        # Parse and add findings
        self._parse_results(out)

        n = count_lines(out)
        p.log.success(f"XSS: {n} candidates found")

    def _parse_results(self, out: str):
        if not os.path.isfile(out): return
        with open(out) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                urls = re.findall(r'https?://\S+', line)
                if not urls: continue
                sev = "high"
                if "POC" in line or "Confirmed" in line:
                    self.p.add_finding(sev, "XSS", urls[0], line[:100], "dalfox")
                elif "kxss" in line.lower() or "reflected" in line.lower():
                    self.p.add_finding("medium", "XSS_CANDIDATE", urls[0],
                                       line[:80], "kxss")
