#!/usr/bin/env python3
# modules/step24_smuggling.py — HTTP Request Smuggling Detection
import os
from core.utils import safe_read

class SmugglingStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        urls = safe_read(self.f.get("live_hosts",""))[:20]
        out  = os.path.join(self.p.out, f"{self.p.prefix}_smuggling.txt")
        found = 0

        # CL.TE smuggling probe
        CL_TE_PAYLOAD = (
            "POST / HTTP/1.1\r\n"
            "Host: TARGET\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
            "0\r\n\r\nG"
        )

        # TE.CL smuggling probe
        TE_CL_PAYLOAD = (
            "POST / HTTP/1.1\r\n"
            "Host: TARGET\r\n"
            "Content-Length: 3\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
            "8\r\n"
            "SMUGGLED\r\n"
            "0\r\n\r\n"
        )

        # Use smuggler tool if available, else basic probe
        for url in urls:
            host = url.replace("https://","").replace("http://","").split("/")[0]

            # Try smuggler.py if available
            result = self.p.shell(
                f"python3 /usr/share/smuggler/smuggler.py -u '{url}' "
                f"--quiet 2>/dev/null | head -5",
                timeout=30)

            if "vulnerable" in result.lower() or "CL.TE" in result or "TE.CL" in result:
                line = f"SMUGGLING: {url} | {result.strip()[:100]}"
                with open(out,"a") as f: f.write(line+"\n")
                self.p.add_finding("critical","HTTP_SMUGGLING",url,
                                   result.strip()[:100],"smuggler")
                found += 1
                continue

            # Basic timing-based detection
            timing_result = self.p.shell(
                f"curl -sk --connect-timeout 10 "
                f"-X POST '{url}' "
                f"-H 'Transfer-Encoding: chunked' "
                f"-H 'Content-Length: 6' "
                f"-d '0\\r\\n\\r\\n' "
                f"-o /dev/null -w '%{{time_total}}'",
                timeout=15)

            try:
                elapsed = float(timing_result.strip())
                if elapsed > 8:
                    line = f"SMUGGLING_TIMING: {url} | response delay {elapsed:.1f}s"
                    with open(out,"a") as f: f.write(line+"\n")
                    self.p.add_finding("high","HTTP_SMUGGLING_POTENTIAL",url,
                                       f"Timing anomaly: {elapsed:.1f}s","timing")
                    found += 1
            except Exception:
                pass

        self.log.success(f"Smuggling: {found} findings")
