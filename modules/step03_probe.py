#!/usr/bin/env python3
# modules/step03_probe.py — HTTP Probe (live hosts via httpx)
# MilkyWay Intelligence | Author: Sharlix

import os
from core.utils import count_lines, FormatFixer, safe_read


class Step03Probe:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p   = self.p
        fmt = p.files.get("fmt_domain","")
        res = p.files.get("resolved","")
        sub = p.files.get("subdomains","")
        out = p.files["live_hosts"]
        t   = p.tmgr.get

        # Pick best input
        input_file = ""
        for f in [fmt, res, sub]:
            if f and os.path.isfile(f) and count_lines(f) > 0:
                input_file = f
                break

        if not input_file:
            # Single target mode
            tgt = p.target.strip()
            if not tgt.startswith("http"):
                tgt = "https://" + tgt
            with open(out,"w") as f:
                f.write(tgt + "\n")
            p.log.success("Probe: single target mode")
            return

        p.log.info(f"Probing {count_lines(input_file)} hosts")

        cookie_flag = ""
        if hasattr(p.args,"cookie") and p.args.cookie:
            cookie_flag = f'-H "Cookie: {p.args.cookie}"'

        # httpx probe
        p.shell(
            f"httpx -l {input_file} -silent -title -status-code "
            f"-follow-redirects -threads 100 "
            f"-rate-limit {p.args.rate if hasattr(p.args,'rate') else 1000} "
            f"{cookie_flag} "
            f"-o {out} 2>/dev/null",
            label="httpx probe", tool_name="httpx", timeout=t("httpx")
        )

        # WAF detection
        waf = p.shell(
            f"wafw00f $(head -1 {out} 2>/dev/null | cut -d' ' -f1) 2>/dev/null | head -5",
            label="WAF detect", timeout=30
        )
        if waf:
            p.log.info(f"  WAF: {waf.strip()[:80]}")
            for waf_name in ["Cloudflare","Akamai","Imperva","F5","Sucuri","Wordfence"]:
                if waf_name.lower() in waf.lower():
                    p.ceo.set_waf_detected(waf_name)
                    break

        # Format output
        FormatFixer.fix(out, p.files["fmt_url"],  "url")
        FormatFixer.fix(out, p.files["fmt_host"], "host")

        n = count_lines(out)
        p.log.success(f"Live hosts: {n}")
        if n == 0:
            p.log.warn("No live hosts found — check connectivity or target format")
