#!/usr/bin/env python3
import os
from core.utils import FormatFixer, count_lines

class NucleiStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        src = self.f["live_hosts"]
        if not os.path.isfile(src) or count_lines(src)==0: src = self.f["subdomains"]
        url_file = self.f["fmt_url"]
        FormatFixer.fix(src, url_file, "url")

        nuclei_out = self.f["nuclei_results"]
        proxy_flag = f"-proxy {self.p.tor.proxy_url()}" if self.p.tor and self.p.tor.is_running() else ""

        # Custom templates path
        custom_tpl = self.p.cfg.get("nuclei_templates","")
        tpl_flag   = f"-t {custom_tpl}" if custom_tpl and os.path.isdir(custom_tpl) else ""

        # M7 custom templates
        m7_tpl = os.path.join(os.path.dirname(__file__),"..","templates","nuclei","m7-custom")
        if os.path.isdir(m7_tpl):
            tpl_flag += f" -t {m7_tpl}"

        # Auth flags
        auth_flag = ""
        if getattr(self.p.args,"cookie",None):
            auth_flag = f"-H 'Cookie: {self.p.args.cookie}'"

        self.p.shell(
            f"nuclei -l {url_file} "
            f"-silent -severity critical,high,medium,low "
            f"-o {nuclei_out} -stats -no-color "
            f"{tpl_flag} {proxy_flag} {auth_flag} 2>/dev/null",
            label="nuclei scan", use_tor=bool(self.p.tor), timeout=1800)

        self._parse(nuclei_out)
        n = count_lines(nuclei_out)
        self.log.success(f"Nuclei: {n} findings → {os.path.basename(nuclei_out)}")

    def _parse(self, path):
        if not os.path.isfile(path): return
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                sev = "medium"
                for s in ["critical","high","medium","low"]:
                    if f"[{s}]" in line.lower(): sev=s; break
                self.p.add_finding(sev, "NUCLEI", line, tool="nuclei")
