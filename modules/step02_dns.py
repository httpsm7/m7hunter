#!/usr/bin/env python3
# modules/step02_dns.py — DNS Resolution
# Input format: bare domain  (domain only — dnsx/massdns requirement)
# Output: resolved.txt + dns_records.txt

import os
from core.utils import FormatFixer, count_lines

class DNSStep:
    def __init__(self, pipeline):
        self.p   = pipeline
        self.log = pipeline.log
        self.f   = pipeline.files

    def run(self):
        # ── Auto-fix: dnsx needs bare domain (no https://) ───────────
        subs = self.f["subdomains"]
        if not os.path.isfile(subs) or count_lines(subs) == 0:
            # Fallback: use raw target as single subdomain
            open(subs, "w").write(
                self.p.target.replace("https://","").replace("http://","") + "\n"
            )

        domain_file = self.f["fmt_domain"]
        FormatFixer.fix(subs, domain_file, "domain")   # ensure bare domains only

        resolved = self.f["resolved"]

        # ── DNSX — resolve A/CNAME records ────────────────────────────
        self.p.shell(
            f"dnsx -l {domain_file} -silent -a -cname -resp -o {resolved} 2>/dev/null",
            label="dnsx resolution"
        )

        if count_lines(resolved) == 0:
            # Fallback: use subdomains as resolved
            self.p.shell(f"cp {domain_file} {resolved}")

        # ── DNS records for root domain ───────────────────────────────
        tgt = self.p.target.replace("https://","").replace("http://","").split("/")[0]
        dns_out = self.f["dns_records"]
        self.p.shell(f"dig +short A {tgt}     >> {dns_out} 2>/dev/null", label="dig A")
        self.p.shell(f"dig +short MX {tgt}    >> {dns_out} 2>/dev/null", label="dig MX")
        self.p.shell(f"dig +short TXT {tgt}   >> {dns_out} 2>/dev/null", label="dig TXT")
        self.p.shell(f"dig +short NS {tgt}    >> {dns_out} 2>/dev/null", label="dig NS")
        self.p.shell(f"dig +short CNAME {tgt} >> {dns_out} 2>/dev/null", label="dig CNAME")
        self.p.shell(f"dig +short TXT _dmarc.{tgt} >> {dns_out} 2>/dev/null", label="dig DMARC")

        n = count_lines(resolved)
        self.log.success(f"Resolved hosts: {n} → {os.path.basename(resolved)}")
