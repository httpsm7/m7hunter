#!/usr/bin/env python3
import os
from core.utils import FormatFixer, count_lines

class SubdomainStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        FormatFixer.fix(self.f["raw_input"], self.f["fmt_domain"], "domain")
        tgt = open(self.f["raw_input"]).read().strip().split("\n")[0]
        tgt = tgt.replace("https://","").replace("http://","").split("/")[0].split(":")[0]
        subs = self.f["subdomains"]

        # subfinder — fast passive
        self.p.shell(f"subfinder -d {tgt} -silent -all 2>/dev/null",
                     label="subfinder passive", append_file=subs)

        # amass — with adaptive timeout (300s max, not unlimited)
        self.p.shell(f"timeout 300 amass enum -passive -d {tgt} 2>/dev/null",
                     label="amass passive", append_file=subs, timeout=320)

        # crt.sh
        self.p.shell(
            f"curl -s --connect-timeout 15 --max-time 30 "
            f"'https://crt.sh/?q=%.{tgt}&output=json' "
            f"| jq -r '.[].name_value' 2>/dev/null | sed 's/\\*\\.//g'",
            label="crt.sh", append_file=subs, use_tor=bool(self.p.tor))
        self.p.bypass.jitter()

        # waybackurls subdomains
        self.p.shell(
            f"echo {tgt} | waybackurls 2>/dev/null "
            f"| grep -oP 'https?://[^/]+' | sed 's|https\\?://||' | sort -u",
            label="waybackurls subs", append_file=subs)

        # Shodan passive (if key available)
        shodan_key = self.p.cfg.get("shodan_key","")
        if shodan_key:
            self.p.shell(
                f"curl -s 'https://api.shodan.io/dns/domain/{tgt}?key={shodan_key}' "
                f"| jq -r '.subdomains[]? // empty' 2>/dev/null "
                f"| sed 's/$/.{tgt}/'",
                label="shodan subdomains", append_file=subs)

        # VirusTotal passive (if key available)
        vt_key = self.p.cfg.get("vt_key","")
        if vt_key:
            self.p.shell(
                f"curl -s --connect-timeout 15 "
                f"'https://www.virustotal.com/vtapi/v2/domain/report?apikey={vt_key}&domain={tgt}' "
                f"| jq -r '.subdomains[]? // empty' 2>/dev/null",
                label="virustotal subs", append_file=subs)

        # Deep brute-force
        if self.p.args.deep or self.p.args.stealth:
            wl = self._wordlist()
            if wl:
                self.p.shell(f"subfinder -d {tgt} -w {wl} -silent 2>/dev/null",
                             label="subfinder brute", append_file=subs)

        # Deduplicate, remove wildcards
        self.p.shell(f"sort -u {subs} -o {subs} 2>/dev/null")
        self.p.shell(f"sed -i '/^\\*/d; /^$/d; /^-/d' {subs} 2>/dev/null")

        n = count_lines(subs)
        self.log.success(f"Subdomains: {n} → {os.path.basename(subs)}")

    def _wordlist(self):
        for c in [
            self.p.args.wordlist if hasattr(self.p.args,'wordlist') else None,
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ]:
            if c and os.path.isfile(c): return c
        return None
