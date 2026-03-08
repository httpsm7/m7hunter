#!/usr/bin/env python3
# modules/step13_takeover.py
# subzy needs: bare domains file
import os
from core.utils import FormatFixer, count_lines

class TakeoverStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        # subzy: needs bare domain list
        domain_file = self.f["fmt_domain"]
        FormatFixer.fix(self.f["subdomains"], domain_file, "domain")

        takeover_out = self.f["takeover_results"]

        self.p.shell(
            f"subzy run --targets {domain_file} "
            f"--output {takeover_out} --hide-fails 2>/dev/null",
            label="subzy takeover"
        )

        n = count_lines(takeover_out)
        if n>0: self.p.add_finding("critical","SUBDOMAIN_TAKEOVER", takeover_out,
                                    f"{n} potential takeovers", "subzy")
        self.log.success(f"Takeover check done: {n} → {os.path.basename(takeover_out)}")
