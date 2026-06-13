#!/usr/bin/env python3
# modules/step01_subdomain.py — Subdomain Enumeration V7 (Upgraded)
# Blueprint Fix: Added alterx permutation fuzzing + crt.sh CT logs
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY
import os, urllib.request, json
from core.utils import count_lines
from core.error_handler import get_handler

class Step01Subdomain:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        t   = self.p.target.replace("https://","").replace("http://","").split("/")[0]
        out = self.f["subdomains"]
        self.log.info(f"Subdomain enum: {t}")

        # 1. Passive enumeration tools
        for cmd, label in [
            (f"subfinder -d {t} -all -recursive -silent 2>/dev/null", "subfinder"),
            (f"amass enum -passive -d {t} -silent 2>/dev/null", "amass"),
            (f"assetfinder --subs-only {t} 2>/dev/null", "assetfinder"),
        ]:
            self.p.shell(cmd, label=label, append_file=out, timeout=300)

        # 2. Certificate Transparency (crt.sh) — Blueprint Fix
        try:
            ct_subs = self._crtsh(t)
            if ct_subs:
                with open(out,"a") as f: f.write("\n".join(ct_subs)+"\n")
                self.log.info(f"  crt.sh: {len(ct_subs)} subdomains")
        except Exception as e:
            get_handler().capture("step01_subdomain", e, "crtsh")

        # 3. Permutation fuzzing with alterx — Blueprint Fix
        try:
            self.p.shell(f"echo {t} | alterx -enrich 2>/dev/null | head -500",
                         label="alterx", append_file=out, timeout=120)
        except Exception as e:
            get_handler().capture("step01_subdomain", e, "alterx")

        # 4. Deduplicate
        self.p.shell(f"sort -u {out} -o {out} 2>/dev/null")
        self.log.success(f"Subdomains: {count_lines(out)}")

    def _crtsh(self, domain: str) -> list:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent":"M7Hunter/7.0"})
        resp = urllib.request.urlopen(req, timeout=15)
        data = json.loads(resp.read().decode())
        subs = set()
        for entry in data:
            for name in entry.get("name_value","").split("\n"):
                name = name.strip().lstrip("*.")
                if name.endswith(f".{domain}") or name == domain:
                    subs.add(name)
        return list(subs)
