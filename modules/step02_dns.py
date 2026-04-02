#!/usr/bin/env python3
# modules/step02_dns.py — DNS Resolution + Record Enumeration
# MilkyWay Intelligence | Author: Sharlix

import os
from core.utils import count_lines, FormatFixer, safe_read


class Step02Dns:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p   = self.p
        src = p.files.get("subdomains","")
        fmt = p.files.get("fmt_domain","")
        out = p.files["resolved"]
        dns = p.files["dns_records"]
        t   = p.tmgr.get
        h   = p.bypass.headers()

        input_file = fmt if os.path.isfile(fmt) and count_lines(fmt) > 0 else src
        if not os.path.isfile(input_file) or count_lines(input_file) == 0:
            p.log.warn("DNS: no subdomains to resolve — skipping")
            return

        p.log.info(f"Resolving {count_lines(input_file)} subdomains")

        # dnsx - resolve A records
        p.shell(
            f"dnsx -l {input_file} -silent -a -resp -o {out} -t 100 2>/dev/null",
            label="dnsx resolve", tool_name="dnsx", timeout=t("dnsx")
        )

        # dnsx - all record types (for zone transfer / misconfig detection)
        p.shell(
            f"dnsx -l {input_file} -silent -a -aaaa -cname -mx -ns -txt "
            f"-resp -o {dns} -t 100 2>/dev/null",
            label="dnsx full records", tool_name="dnsx", timeout=t("dnsx")
        )

        # Check zone transfer
        tgt = p.target.replace("https://","").replace("http://","").split("/")[0]
        zone = p.shell(
            f"dig axfr {tgt} @$(dig NS {tgt} +short | head -1) 2>/dev/null | head -30",
            label="zone transfer check", timeout=20
        )
        if zone and ("IN" in zone or "SOA" in zone):
            p.add_finding("critical", "DNS_ZONE_TRANSFER", f"dns://{tgt}",
                           "Zone transfer allowed — all DNS records exposed",
                           tool="dig")

        n = count_lines(out)
        p.log.success(f"Resolved: {n} hosts")
        FormatFixer.fix(out, p.files["fmt_domain"], 'domain')
