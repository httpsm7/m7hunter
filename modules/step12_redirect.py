#!/usr/bin/env python3
# modules/step12_redirect.py
import os
from core.utils import count_lines

class RedirectStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        urls     = self.f["urls"]
        redir_out= self.f["redirect_results"]

        self.p.shell(f"cat {urls} 2>/dev/null | gf redirect > /tmp/m7_redir_params.txt 2>/dev/null", label="gf redirect")

        self.p.shell(
            f"cat /tmp/m7_redir_params.txt | head -100 | while read u; do "
            f"  loc=$(curl -sk -o /dev/null -w '%{{redirect_url}}' "
            f"  --connect-timeout 5 \"$u\"); "
            f"  [ ! -z \"$loc\" ] && echo \"$u → $loc\" >> {redir_out}; "
            f"done",
            label="open redirect probe", use_tor=bool(self.p.tor)
        )

        n = count_lines(redir_out)
        if n>0: self.p.add_finding("medium","OPEN_REDIRECT", redir_out, f"{n} redirects", "curl")
        self.log.success(f"Redirects: {n} → {os.path.basename(redir_out)}")
