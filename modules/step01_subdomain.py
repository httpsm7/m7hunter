#!/usr/bin/env python3
# modules/step01_subdomain.py — Subdomain Enumeration
# Input format needed: bare domain (example.com)
# Output: subdomains.txt (one domain per line)

import os
from core.utils import FormatFixer, count_lines

class SubdomainStep:
    NAME = "SUBDOMAIN ENUMERATION"

    def __init__(self, pipeline):
        self.p   = pipeline
        self.log = pipeline.log
        self.out = pipeline.out
        self.f   = pipeline.files

    def run(self):
        # ── Prepare input: need bare domain ──────────────────────────
        fmt_in = self.f["fmt_domain"]
        FormatFixer.fix(self.f["raw_input"], fmt_in, "domain")
        target = open(self.f["raw_input"]).read().strip().split("\n")[0]
        target_clean = target.replace("https://","").replace("http://","").split("/")[0]

        subs = self.f["subdomains"]

        # ── Subfinder (passive) ───────────────────────────────────────
        self.p.shell(
            f"subfinder -d {target_clean} -silent -all 2>/dev/null",
            label="subfinder passive",
            append_file=subs
        )

        # ── Amass passive ─────────────────────────────────────────────
        self.p.shell(
            f"amass enum -passive -d {target_clean} 2>/dev/null",
            label="amass passive",
            append_file=subs
        )

        # ── crt.sh ────────────────────────────────────────────────────
        self.p.shell(
            f"curl -s 'https://crt.sh/?q=%.{target_clean}&output=json' "
            f"| jq -r '.[].name_value' 2>/dev/null "
            f"| sed 's/\\*\\.//g'",
            label="crt.sh",
            append_file=subs,
            use_tor=bool(self.p.tor)
        )
        self.p.bypass.jitter()

        # ── Waybackurls for subdomains ─────────────────────────────────
        self.p.shell(
            f"echo {target_clean} | waybackurls 2>/dev/null "
            f"| grep -oP 'https?://[^/]+' | sed 's|https\\?://||' | sort -u",
            label="waybackurls subs",
            append_file=subs
        )

        # ── Active brute-force (deep/stealth mode) ────────────────────
        wl = self._find_wordlist()
        if wl and (self.p.args.deep or self.p.args.stealth):
            self.log.info(f"  ↳ Brute-force with {wl}")
            self.p.shell(
                f"subfinder -d {target_clean} -w {wl} -silent 2>/dev/null",
                label="subfinder brute",
                append_file=subs
            )

        # ── Deduplicate ───────────────────────────────────────────────
        self.p.shell(f"sort -u {subs} -o {subs}")
        # Remove wildcards and blank lines
        self.p.shell(f"sed -i '/^\\*/d; /^$/d' {subs}")

        n = count_lines(subs)
        self.log.success(f"Subdomains found: {n} → {os.path.basename(subs)}")

    def _find_wordlist(self):
        candidates = [
            self.p.args.wordlist,
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ]
        for c in candidates:
            if c and os.path.isfile(c):
                return c
        return None
