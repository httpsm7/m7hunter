#!/usr/bin/env python3
# modules/step08_sqli.py
import os
from core.utils import FormatFixer, count_lines

class SQLiStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        urls = self.f["urls"]
        if not os.path.isfile(urls) or count_lines(urls)==0:
            FormatFixer.fix(self.f["live_hosts"], self.f["fmt_url"], "url")
            urls = self.f["fmt_url"]

        sqli_params = self.f["sqli_params"]
        sqli_out    = os.path.join(self.p.out, f"{self.p.prefix}_sqlmap")

        # gf filter
        self.p.shell(f"cat {urls} 2>/dev/null | gf sqli > {sqli_params} 2>/dev/null", label="gf sqli")

        if count_lines(sqli_params) == 0:
            self.log.warn("No SQLi parameters found")
            return

        # sqlmap
        self.p.shell(
            f"sqlmap -m {sqli_params} "
            f"--batch --random-agent "
            f"--level=2 --risk=2 "
            f"--output-dir={sqli_out} "
            f"--forms --crawl=2 "
            f"--no-logging 2>/dev/null",
            label="sqlmap", use_tor=bool(self.p.tor), timeout=1200
        )
        self.p.add_finding("high","SQLI", sqli_params,
                            f"{count_lines(sqli_params)} params tested", "sqlmap")
        self.log.success(f"SQLi scan done → {sqli_out}/")
