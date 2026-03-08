#!/usr/bin/env python3
# modules/step07_xss.py
import os
from core.utils import FormatFixer, count_lines

class XSSStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        urls = self.f["urls"]
        if not os.path.isfile(urls) or count_lines(urls)==0:
            urls = self.f["fmt_url"]
            if not os.path.isfile(urls): FormatFixer.fix(self.f["live_hosts"], urls, "url")

        xss_params = os.path.join(self.p.out, f"{self.p.prefix}_xss_params.txt")
        xss_out    = self.f["xss_results"]

        # gf pattern filter
        self.p.shell(f"cat {urls} 2>/dev/null | gf xss > {xss_params} 2>/dev/null", label="gf xss filter")

        src = xss_params if count_lines(xss_params)>0 else urls

        # Dalfox
        self.p.shell(
            f"dalfox file {src} --skip-bav --silence --no-color "
            f"-o {xss_out} 2>/dev/null",
            label="dalfox xss", use_tor=bool(self.p.tor), timeout=600
        )
        # kxss
        self.p.shell(
            f"cat {src} | kxss 2>/dev/null", label="kxss",
            append_file=xss_out
        )

        n = count_lines(xss_out)
        if n>0: self.p.add_finding("high","XSS", xss_out, f"{n} potential XSS", "dalfox/kxss")
        self.log.success(f"XSS results: {n} → {os.path.basename(xss_out)}")
