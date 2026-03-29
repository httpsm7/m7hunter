#!/usr/bin/env python3
# modules/step13_takeover.py — FIXED: subzy correct flags
import os
from core.utils import FormatFixer, count_lines

class TakeoverStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        domain_file  = self.f["fmt_domain"]
        FormatFixer.fix(self.f["subdomains"], domain_file, "domain")
        takeover_out = self.f["takeover_results"]

        # subzy FIXED — no --output flag (doesn't exist), use append_file
        self.p.shell(
            f"subzy run --targets {domain_file} --hide-fails --vuln 2>/dev/null",
            label="subzy takeover", append_file=takeover_out, tool_name="subzy")

        # Also check with nuclei takeover templates
        self.p.shell(
            f"nuclei -l {domain_file} -t takeovers/ -silent -no-color 2>/dev/null",
            label="nuclei takeover templates", append_file=takeover_out)

        n = count_lines(takeover_out)
        if n>0:
            self.p.add_finding("critical","SUBDOMAIN_TAKEOVER",takeover_out,
                                f"{n} potential takeovers","subzy+nuclei")
        self.log.success(f"Takeover: {n}")
