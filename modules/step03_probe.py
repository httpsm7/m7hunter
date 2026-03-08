#!/usr/bin/env python3
# modules/step03_probe.py — HTTP Probe
# Input format: bare domain / host  (httpx handles https:// internally)
# Output: live_hosts.txt  (https://example.com format)

import os
from core.utils import FormatFixer, count_lines

class ProbeStep:
    def __init__(self, pipeline):
        self.p   = pipeline
        self.log = pipeline.log
        self.f   = pipeline.files

    def run(self):
        # ── Input: resolved hosts OR subdomains ───────────────────────
        src = self.f["resolved"]
        if not os.path.isfile(src) or count_lines(src) == 0:
            src = self.f["subdomains"]
        if not os.path.isfile(src) or count_lines(src) == 0:
            src = self.f["raw_input"]

        # ── Auto-fix: httpx accepts bare domains or full URLs ─────────
        # We feed bare domains; httpx will probe both http + https
        host_file = self.f["fmt_host"]
        FormatFixer.fix(src, host_file, "domain")

        live    = self.f["live_hosts"]
        threads = self.p.args.threads
        ua      = self.p.bypass.ua()

        # ── HTTPX probe ───────────────────────────────────────────────
        self.p.shell(
            f"httpx -l {host_file} "
            f"-silent -threads {threads} "
            f"-status-code -title -tech-detect -follow-redirects "
            f"-H 'User-Agent: {ua}' "
            f"-o {live} 2>/dev/null",
            label="httpx probe",
            use_tor=bool(self.p.tor)
        )

        # If httpx produced nothing, fall back
        if count_lines(live) == 0:
            self.p.shell(
                f"httpx -l {host_file} -silent -threads {threads} -o {live} 2>/dev/null",
                label="httpx probe (fallback)"
            )

        # ── GAU — gather all known URLs ───────────────────────────────
        tgt_clean = self.p.target.replace("https://","").replace("http://","").split("/")[0]
        self.p.shell(
            f"gau --blacklist png,jpg,gif,svg,css,woff --timeout 30 {tgt_clean} 2>/dev/null",
            label="gau",
            append_file=self.f["gau_urls"],
            use_tor=bool(self.p.tor)
        )
        self.p.bypass.jitter()

        # ── Waybackurls ───────────────────────────────────────────────
        self.p.shell(
            f"echo {tgt_clean} | waybackurls 2>/dev/null",
            label="waybackurls",
            append_file=self.f["wayback_urls"]
        )

        n = count_lines(live)
        self.log.success(f"Live hosts: {n} → {os.path.basename(live)}")
