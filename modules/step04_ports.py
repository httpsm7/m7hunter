#!/usr/bin/env python3
# modules/step04_ports.py — Port Scanning (naabu + nmap)
# MilkyWay Intelligence | Author: Sharlix

import re
from core.utils import count_lines, safe_read, FormatFixer


class Step04Ports:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p   = self.p
        out = p.files["open_ports"]
        fmt = p.files.get("fmt_host","")
        t   = p.tmgr.get

        if not fmt or count_lines(fmt) == 0:
            p.log.warn("Ports: no resolved hosts — using target directly")
            tgt = p.target.replace("https://","").replace("http://","").split("/")[0]
            with open(p.files.get("fmt_host",""), "w") as f:
                f.write(tgt + "\n")
            fmt = p.files.get("fmt_host","")

        p.log.info("Port scanning (naabu + nmap service detect)")

        # naabu — fast port scan
        p.shell(
            f"naabu -l {fmt} -p 80,443,8080,8443,8888,3000,4000,5000,"
            f"9090,9443,8000,8001,8181,5001,3306,5432,27017,6379 "
            f"-silent -rate 1000 -o {out} 2>/dev/null",
            label="naabu scan", tool_name="naabu", timeout=t("naabu")
        )

        # nmap service version on open ports
        hosts = safe_read(out)[:10]
        if hosts:
            host_list = " ".join(h.split(":")[0] for h in hosts[:5])
            svc = p.shell(
                f"nmap -sV -sC --open -p 80,443,8080,8443,8888,3000,4000 "
                f"--script=http-title,http-headers {host_list} 2>/dev/null | head -60",
                label="nmap service scan", tool_name="nmap", timeout=t("nmap")
            )
            if svc:
                # Check for exposed services
                for svc_name in ["FTP","Telnet","SMTP","POP3","IMAP","Redis","MongoDB","Memcached"]:
                    if svc_name.lower() in svc.lower():
                        p.add_finding("high", "EXPOSED_SERVICE", f"tcp://{hosts[0]}",
                                       f"Exposed {svc_name} service detected", "nmap")

        n = count_lines(out)
        p.log.success(f"Open ports: {n}")
