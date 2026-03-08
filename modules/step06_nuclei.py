#!/usr/bin/env python3
# modules/step06_nuclei.py — Nuclei Vulnerability Scan
# nuclei accepts: https://example.com  OR bare domain

import os
from core.utils import FormatFixer, count_lines

class NucleiStep:
    def __init__(self, pipeline):
        self.p   = pipeline
        self.log = pipeline.log
        self.f   = pipeline.files

    def run(self):
        # ── Input: live hosts with https:// ───────────────────────────
        src = self.f["live_hosts"]
        if not os.path.isfile(src) or count_lines(src) == 0:
            src = self.f["subdomains"]

        url_file = self.f["fmt_url"]
        FormatFixer.fix(src, url_file, "url")

        nuclei_out = self.f["nuclei_results"]
        proxy_flag = f"-proxy {self.p.tor.proxy_url()}" if self.p.tor and self.p.tor.is_running() else ""

        # ── Run Nuclei ────────────────────────────────────────────────
        self.p.shell(
            f"nuclei -l {url_file} "
            f"-silent "
            f"-severity critical,high,medium "
            f"-o {nuclei_out} "
            f"-stats -no-color "
            f"{proxy_flag} 2>/dev/null",
            label="nuclei scan",
            use_tor=bool(self.p.tor),
            timeout=1800
        )

        # ── Parse results ─────────────────────────────────────────────
        self._parse(nuclei_out)
        n = count_lines(nuclei_out)
        self.log.success(f"Nuclei findings: {n} → {os.path.basename(nuclei_out)}")

    def _parse(self, path):
        if not os.path.isfile(path):
            return
        sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                sev = "medium"
                for s in sev_map:
                    if f"[{s}]" in line.lower():
                        sev = s
                        break
                self.p.add_finding(sev, "NUCLEI", line, tool="nuclei")
