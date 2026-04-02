#!/usr/bin/env python3
# modules/step01_subdomain.py — Subdomain Enumeration
# Tools: subfinder, amass, dnsx, assetfinder
# MilkyWay Intelligence | Author: Sharlix

import os
from core.utils import count_lines, FormatFixer


class Step01Subdomain:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p    = self.p
        tgt  = p.target.replace("https://","").replace("http://","").split("/")[0].split(":")[0]
        out  = p.files["subdomains"]
        fmt  = p.files["fmt_domain"]
        t    = p.tmgr.get

        p.log.info(f"Subdomain enum: {tgt}")

        # subfinder
        p.shell(
            f"subfinder -d {tgt} -silent -all -recursive -t 50 "
            f"-o {out} 2>/dev/null",
            label="subfinder", tool_name="subfinder",
            append_file=out, timeout=t("subfinder")
        )

        # assetfinder
        p.shell(
            f"assetfinder --subs-only {tgt} 2>/dev/null",
            label="assetfinder", tool_name="subfinder",
            append_file=out, timeout=60
        )

        # amass passive
        p.shell(
            f"amass enum -passive -d {tgt} -o /tmp/amass_tmp.txt 2>/dev/null "
            f"&& cat /tmp/amass_tmp.txt >> {out}",
            label="amass passive", tool_name="amass",
            timeout=t("amass")
        )

        # crt.sh
        p.shell(
            f'curl -s "https://crt.sh/?q=%.{tgt}&output=json" 2>/dev/null '
            f'| python3 -c "import sys,json; '
            f'[print(e[\'name_value\']) for e in json.load(sys.stdin) if \'name_value\' in e]" '
            f'2>/dev/null',
            label="crt.sh", append_file=out, timeout=30
        )

        # Deduplicate
        FormatFixer.fix(out, fmt, 'domain')
        n = count_lines(fmt)
        p.log.success(f"Subdomains found: {n}")
        if n == 0:
            p.log.warn("No subdomains — check target format (use domain.com not https://)")
