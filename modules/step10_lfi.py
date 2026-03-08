#!/usr/bin/env python3
# modules/step10_lfi.py
import os
from core.utils import FormatFixer, count_lines

class LFIStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        urls = self.f["urls"]
        lfi_params = os.path.join(self.p.out, f"{self.p.prefix}_lfi_params.txt")
        lfi_out    = self.f["lfi_results"]

        self.p.shell(f"cat {urls} 2>/dev/null | gf lfi > {lfi_params} 2>/dev/null", label="gf lfi")

        if count_lines(lfi_params) == 0:
            self.log.warn("No LFI parameters found"); return

        wl = "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"
        if not os.path.isfile(wl):
            wl = "/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt"
        if not os.path.isfile(wl):
            self.log.warn("LFI wordlist not found — skipping ffuf"); return

        # Run ffuf on each param
        self.p.shell(
            f"cat {lfi_params} | head -50 | while read u; do "
            f"  ffuf -u \"$u\" -w {wl}:FUZZ "
            f"  -mc 200 -silent -o /dev/null 2>/dev/null "
            f"  | grep -v 'null' >> {lfi_out}; "
            f"done",
            label="ffuf lfi", use_tor=bool(self.p.tor), timeout=600
        )
        n = count_lines(lfi_out)
        if n>0: self.p.add_finding("high","LFI", lfi_out, f"{n} potential LFI", "ffuf")
        self.log.success(f"LFI scan done → {os.path.basename(lfi_out)}")
