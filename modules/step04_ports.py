#!/usr/bin/env python3
import os
from core.utils import FormatFixer, count_lines

class PortsStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        src = self.f["resolved"] if os.path.isfile(self.f["resolved"]) else self.f["subdomains"]
        host_file = self.f["fmt_host"]
        FormatFixer.fix(src, host_file, "host")

        # Extra strip: remove any https:// that may remain
        self.p.shell(f"sed -i 's|https\\?://||g; s|/.*||; s|:.*||' {host_file} 2>/dev/null")

        ports_out = self.f["open_ports"]
        rate      = self.p.args.rate

        # naabu — fast port scan
        self.p.shell(
            f"naabu -l {host_file} -top-ports 1000 -silent -rate {rate} -o {ports_out} 2>/dev/null",
            label="naabu fast scan")

        # nmap — FIXED: strip all prefixes before feeding to nmap
        nmap_in  = host_file  # already clean bare hosts
        nmap_out = os.path.join(self.p.out, f"{self.p.prefix}_nmap.txt")

        # Verify nmap input is clean (no https://)
        self.p.shell(
            f"grep -v '^https\\?://' {nmap_in} | grep -v '^$' > /tmp/m7_nmap_clean.txt 2>/dev/null")
        clean_count = count_lines("/tmp/m7_nmap_clean.txt")

        if clean_count > 0:
            self.p.shell(
                f"nmap -iL /tmp/m7_nmap_clean.txt "
                f"-sV -T4 --open "
                f"--script=http-title,banner "
                f"-oN {nmap_out} 2>/dev/null",
                label="nmap service scan", timeout=900)
            self._parse_nmap(nmap_out)
        else:
            self.log.warn("nmap: no clean hosts to scan")

        n = count_lines(ports_out)
        self.log.success(f"Open ports: {n} → {os.path.basename(ports_out)}")

    def _parse_nmap(self, nmap_file):
        if not os.path.isfile(nmap_file): return
        INTERESTING = ["ftp","ssh","telnet","smtp","rdp","vnc","mongodb","redis",
                       "elastic","memcached","cassandra","couchdb","mysql","mssql","postgresql"]
        with open(nmap_file) as f:
            for line in f:
                l = line.lower()
                for svc in INTERESTING:
                    if svc in l and "open" in l:
                        self.p.add_finding("medium", f"EXPOSED:{svc.upper()}",
                                           line.strip(), "Interesting service exposed", "nmap")
