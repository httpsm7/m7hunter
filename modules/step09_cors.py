#!/usr/bin/env python3
import os
from core.utils import FormatFixer, count_lines, safe_read

class CORSStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        FormatFixer.fix(self.f["live_hosts"], self.f["fmt_url"], "url")
        cors_out = self.f["cors_results"]
        findings = 0
        EVIL_ORIGINS = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            "https://trusted.evil.com",
        ]
        for url in safe_read(self.f["fmt_url"])[:200]:
            self.p.bypass.jitter()
            for origin in EVIL_ORIGINS[:2]:  # test top 2 for speed
                result = self.p.shell(
                    f"curl -sk -H 'Origin: {origin}' "
                    f"-H 'User-Agent: {self.p.bypass.ua()}' "
                    f"-I '{url}' 2>/dev/null | grep -i 'access-control'",
                    use_tor=bool(self.p.tor))
                if result:
                    with open(cors_out,"a") as f:
                        f.write(f"{url} | Origin: {origin} | {result.strip()}\n")
                    if origin in result.lower() or "access-control-allow-origin: *" in result.lower():
                        sev = "high" if origin in result.lower() else "medium"
                        self.p.add_finding(sev,"CORS_MISCONFIG", url,
                                           f"Reflects: {origin}", "curl")
                        findings += 1
        self.log.success(f"CORS: {findings} misconfigs → {os.path.basename(cors_out)}")
