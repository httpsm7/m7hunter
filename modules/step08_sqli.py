#!/usr/bin/env python3
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
        results_out = self.f["sqli_results"]

        # gf filter with fallback
        self.p.shell(f"cat {urls} | gf sqli > {sqli_params} 2>/dev/null", label="gf sqli")
        if count_lines(sqli_params)==0:
            self.log.warn("gf sqli empty — using URLs with = params")
            self.p.shell(f"grep '=' {urls} | head -50 > {sqli_params} 2>/dev/null")

        if count_lines(sqli_params)==0:
            self.log.warn("No SQLi params found"); return

        # Auth
        cookie_flag = f"--cookie '{self.p.args.cookie}'" if getattr(self.p.args,"cookie",None) else ""

        # Run sqlmap
        self.p.shell(
            f"sqlmap -m {sqli_params} "
            f"--batch --random-agent --level=2 --risk=2 "
            f"--output-dir={sqli_out} --forms --crawl=2 "
            f"{cookie_flag} --no-logging 2>/dev/null",
            label="sqlmap scan", use_tor=bool(self.p.tor), timeout=1200)

        # FIXED: Parse sqlmap output AFTER scan, only add confirmed injections
        self._parse_sqlmap_results(sqli_out, results_out)

        n = count_lines(results_out)
        self.log.success(f"SQLi confirmed: {n} → {os.path.basename(results_out)}")

    def _parse_sqlmap_results(self, sqlmap_dir, results_out):
        """Parse sqlmap output directory for CONFIRMED injections only."""
        if not os.path.isdir(sqlmap_dir): return
        confirmed = 0
        for root, dirs, files in os.walk(sqlmap_dir):
            for fname in files:
                if fname.endswith(".txt"):
                    fpath = os.path.join(root, fname)
                    try:
                        content = open(fpath).read()
                        # sqlmap writes "sqlmap identified the following injection point"
                        if "injection point" in content.lower() and "Parameter:" in content:
                            lines = content.split("\n")
                            for i, line in enumerate(lines):
                                if "Parameter:" in line:
                                    detail = line.strip()
                                    url = fname.replace(".txt","")
                                    with open(results_out,"a") as f:
                                        f.write(f"{url} | {detail}\n")
                                    self.p.add_finding("critical","SQLI_CONFIRMED",
                                                       url, detail, "sqlmap")
                                    confirmed += 1
                    except: pass
        if confirmed == 0:
            self.log.info("SQLi: no confirmed injections found")
