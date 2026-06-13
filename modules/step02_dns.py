#!/usr/bin/env python3
# modules/step02_dns.py — DNS Resolution V7 (Upgraded)
# Blueprint Fix: Zone transfer attempt + CNAME chain following
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY
import os, re
from core.utils import count_lines
from core.error_handler import get_handler

TAKEOVER_SIGNATURES = [
    "There is no app configured","herokucdn.com","github.io",
    "amazonaws.com/404","netlify.app","azurewebsites.net","pantheonsite.io",
    "fastly.net/404","shopify.com/404","cargo.site",
]

class Step02Dns:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        subs = self.f["subdomains"]; out = self.f["resolved"]
        if not os.path.isfile(subs) or count_lines(subs)==0:
            self.log.warn("DNS: no subdomains — skipping"); return

        # 1. Mass DNS resolution
        self.p.shell(f"dnsx -l {subs} -a -cname -resp -silent -o {out} 2>/dev/null",
                     label="dnsx resolve", timeout=300)

        # 2. Wildcard detection
        t = self.p.target.replace("https://","").replace("http://","").split("/")[0]
        wc = self.p.shell(f"dig +short randomxyz999.{t} 2>/dev/null")
        if wc.strip():
            self.log.warn(f"  Wildcard DNS detected for {t} — results may be noisy")

        # 3. Zone transfer attempt — Blueprint Fix
        try: self._zone_transfer(t)
        except Exception as e: get_handler().capture("step02_dns", e, "zone_transfer")

        # 4. CNAME chain following — Blueprint Fix
        try: self._follow_cnames(out)
        except Exception as e: get_handler().capture("step02_dns", e, "cname_chain")

        self.log.success(f"DNS: {count_lines(out)} resolved hosts")

    def _zone_transfer(self, domain: str):
        ns_raw = self.p.shell(f"dig NS {domain} +short 2>/dev/null")
        if not ns_raw: return
        for ns in ns_raw.strip().split("\n"):
            ns = ns.strip().rstrip(".")
            if not ns: continue
            result = self.p.shell(f"dig axfr {domain} @{ns} 2>/dev/null", timeout=15)
            if result and "AXFR" in result and "SOA" in result:
                self.log.warn(f"  ⚠ Zone transfer SUCCEEDED via {ns}!")
                zt_file = os.path.join(self.p.out, f"{self.p.prefix}_zone_transfer.txt")
                with open(zt_file,"w") as f: f.write(result)
                self.p.add_finding("high","DNS_ZONE_TRANSFER",
                    f"{domain}@{ns}", f"Full zone data saved to {zt_file}", "dig-axfr",
                    response=result[:300], confidence=0.99, status="confirmed")

    def _follow_cnames(self, resolved_file: str):
        if not os.path.isfile(resolved_file): return
        cnames = re.findall(r"CNAME\s+(\S+)", open(resolved_file).read(), re.IGNORECASE)
        for cname in cnames[:30]:
            cname = cname.rstrip(".")
            try:
                import urllib.request
                req = urllib.request.Request(f"http://{cname}", headers={"User-Agent":"M7Hunter/7.0"})
                resp = urllib.request.urlopen(req, timeout=8)
                body = resp.read(1000).decode(errors="ignore")
                for sig in TAKEOVER_SIGNATURES:
                    if sig.lower() in body.lower():
                        self.p.add_finding("critical","CNAME_TAKEOVER_CHAIN",
                            f"http://{cname}", f"Dangling CNAME: {sig}", "cname-check",
                            confidence=0.92, status="confirmed")
                        break
            except Exception as _e:
                from core.error_handler import get_handler
                get_handler().capture("step02_dns", _e)
