#!/usr/bin/env python3
# modules/step04_ports.py — Port Scan
# naabu / nmap need: bare host or IP  (NOT https://example.com)
# masscan needs: IP only

import os
from core.utils import FormatFixer, count_lines

class PortsStep:
    def __init__(self, pipeline):
        self.p   = pipeline
        self.log = pipeline.log
        self.f   = pipeline.files

    def run(self):
        # ── Auto-fix: strip https:// for naabu/nmap ──────────────────
        src = self.f["resolved"] if os.path.isfile(self.f["resolved"]) \
              else self.f["subdomains"]

        host_file = self.f["fmt_host"]
        FormatFixer.fix(src, host_file, "host")   # bare host, no scheme

        ports_out = self.f["open_ports"]
        threads   = self.p.args.threads
        rate      = self.p.args.rate

        # ── Naabu — fast port discovery ───────────────────────────────
        self.p.shell(
            f"naabu -l {host_file} "
            f"-top-ports 1000 "
            f"-silent "
            f"-rate {rate} "
            f"-o {ports_out} 2>/dev/null",
            label="naabu fast scan"
        )

        # ── Nmap — service/version detection on discovered ports ──────
        # nmap accepts: domain / IP (no https://)
        nmap_input = host_file   # already fmt_host (bare)
        nmap_out   = os.path.join(self.p.out, f"{self.p.prefix}_nmap.txt")

        self.p.shell(
            f"nmap -iL {nmap_input} "
            f"-sV -T4 --open "
            f"--script=http-title,banner "
            f"-oN {nmap_out} 2>/dev/null",
            label="nmap service scan",
            timeout=900
        )

        # ── Parse interesting services ────────────────────────────────
        self._parse_nmap(nmap_out)

        n = count_lines(ports_out)
        self.log.success(f"Open ports: {n} entries → {os.path.basename(ports_out)}")

    def _parse_nmap(self, nmap_file):
        if not os.path.isfile(nmap_file):
            return
        interesting = ["ftp","ssh","telnet","smtp","rdp","vnc","mongodb","redis","elastic"]
        with open(nmap_file) as f:
            for line in f:
                l = line.lower()
                for svc in interesting:
                    if svc in l and "open" in l:
                        self.p.add_finding(
                            "medium", f"OPEN:{svc.upper()}",
                            line.strip(), "Interesting service exposed", "nmap"
                        )
