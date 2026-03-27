#!/usr/bin/env python3
import os
from core.utils import count_lines

class LFIStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        urls     = self.f["urls"]
        lfi_params = os.path.join(self.p.out, f"{self.p.prefix}_lfi_params.txt")
        lfi_out  = self.f["lfi_results"]

        self.p.shell(f"cat {urls} | gf lfi > {lfi_params} 2>/dev/null", label="gf lfi")
        if count_lines(lfi_params)==0:
            self.log.warn("No LFI params found"); return

        wl = None
        for candidate in [
            "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt",
            "/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
        ]:
            if os.path.isfile(candidate): wl=candidate; break

        if not wl:
            self.log.warn("LFI wordlist not found"); return

        auth = f'-H "Cookie: {self.p.args.cookie}"' if getattr(self.p.args,"cookie",None) else ""

        self.p.shell(
            f"cat {lfi_params} | head -50 | while IFS= read -r u; do "
            f"  ffuf -u \"$u\" -w {wl}:FUZZ "
            f"  -mc 200 -ms 0 -silent {auth} 2>/dev/null "
            f"  | grep -v '^$' >> {lfi_out}; "
            f"done",
            label="ffuf lfi", use_tor=bool(self.p.tor), timeout=600)

        n = count_lines(lfi_out)
        if n>0: self.p.add_finding("high","LFI", lfi_out, f"{n} potential LFI", "ffuf")
        self.log.success(f"LFI: {n} → {os.path.basename(lfi_out)}")
