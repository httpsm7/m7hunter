#!/usr/bin/env python3
import os
from core.utils import FormatFixer, count_lines

class DNSStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        subs = self.f["subdomains"]
        if not os.path.isfile(subs) or count_lines(subs)==0:
            tgt = self.p.target.replace("https://","").replace("http://","").split("/")[0]
            open(subs,"w").write(tgt+"\n")

        domain_file = self.f["fmt_domain"]
        FormatFixer.fix(subs, domain_file, "domain")
        resolved = self.f["resolved"]

        # dnsx — resolve A/CNAME
        self.p.shell(f"dnsx -l {domain_file} -silent -a -cname -resp -o {resolved} 2>/dev/null",
                     label="dnsx resolution")

        # Strip dnsx output format: "sub.example.com [1.2.3.4]" → keep only hostname
        self.p.shell(f"sed -i 's/ \\[.*//g' {resolved} 2>/dev/null")

        if count_lines(resolved)==0:
            self.p.shell(f"cp {domain_file} {resolved}")

        # DNS records for root domain
        tgt = self.p.target.replace("https://","").replace("http://","").split("/")[0]
        dns_out = self.f["dns_records"]
        for rec in ["A","MX","TXT","NS","CNAME"]:
            self.p.shell(f"dig +short {rec} {tgt} >> {dns_out} 2>/dev/null", label=f"dig {rec}")
        self.p.shell(f"dig +short TXT _dmarc.{tgt} >> {dns_out} 2>/dev/null", label="dig DMARC")

        n = count_lines(resolved)
        self.log.success(f"Resolved: {n} → {os.path.basename(resolved)}")
