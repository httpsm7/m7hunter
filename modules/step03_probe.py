#!/usr/bin/env python3
import os
from core.utils import FormatFixer, count_lines

class ProbeStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        src = self.f["resolved"]
        if not os.path.isfile(src) or count_lines(src)==0: src = self.f["subdomains"]
        if not os.path.isfile(src) or count_lines(src)==0: src = self.f["raw_input"]

        # Fix: feed bare domains to httpx — output will be URLs only (no status/title suffix)
        host_file = self.f["fmt_host"]
        FormatFixer.fix(src, host_file, "domain")

        live    = self.f["live_hosts"]
        threads = self.p.args.threads
        ua      = self.p.bypass.ua()

        # httpx: output ONLY URLs (-silent, no extra flags that add [200][Title])
        # Use -probe to confirm liveness, output format stays clean
        self.p.shell(
            f"httpx -l {host_file} -silent -threads {threads} "
            f"-follow-redirects -mc 200,201,301,302,403 "
            f"-H 'User-Agent: {ua}' "
            f"-o {live} 2>/dev/null",
            label="httpx probe", use_tor=bool(self.p.tor))

        # Fallback
        if count_lines(live)==0:
            self.p.shell(f"httpx -l {host_file} -silent -threads {threads} -o {live} 2>/dev/null",
                         label="httpx fallback")

        # After httpx, run FormatFixer to clean any stray suffixes
        FormatFixer.fix(live, live+".clean", "url")
        if count_lines(live+".clean") > 0:
            self.p.shell(f"mv {live}.clean {live}")

        # gau — with timeout to prevent hang
        tgt = self.p.target.replace("https://","").replace("http://","").split("/")[0]
        self.p.shell(
            f"timeout {self.p.cfg.get('timeout_gau',120)} gau "
            f"--blacklist png,jpg,gif,svg,css,woff,ttf,ico --timeout 30 {tgt} 2>/dev/null",
            label="gau", append_file=self.f["gau_urls"],
            use_tor=bool(self.p.tor), timeout=130)
        self.p.bypass.jitter()

        # waybackurls
        self.p.shell(f"echo {tgt} | waybackurls 2>/dev/null",
                     label="waybackurls", append_file=self.f["wayback_urls"])

        n = count_lines(live)
        self.log.success(f"Live hosts: {n} → {os.path.basename(live)}")
