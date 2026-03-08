#!/usr/bin/env python3
# modules/step09_cors.py
import os
from core.utils import FormatFixer, count_lines, safe_read

class CORSStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        src = self.f["live_hosts"]
        url_file = self.f["fmt_url"]
        FormatFixer.fix(src, url_file, "url")

        cors_out = self.f["cors_results"]
        findings = 0

        for url in safe_read(url_file)[:200]:   # cap at 200
            self.p.bypass.jitter()
            result = self.p.shell(
                f"curl -sk -H 'Origin: https://evil.com' "
                f"-H 'User-Agent: {self.p.bypass.ua()}' "
                f"-I '{url}' 2>/dev/null "
                f"| grep -i 'access-control'",
                use_tor=bool(self.p.tor)
            )
            if result:
                line = f"{url} | {result.strip()}"
                with open(cors_out, "a") as f:
                    f.write(line + "\n")
                # Check for wildcard or reflected origin
                if "evil.com" in result or "access-control-allow-origin: *" in result.lower():
                    self.p.add_finding("high","CORS_MISCONFIG", url, result.strip(), "curl")
                    findings += 1

        self.log.success(f"CORS misconfigs: {findings} → {os.path.basename(cors_out)}")
