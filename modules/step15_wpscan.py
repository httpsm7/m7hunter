#!/usr/bin/env python3
# modules/step15_wpscan.py
import os
from core.utils import FormatFixer, ensure_dir, safe_read

class WPScanStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        url_file = self.f["fmt_url"]
        FormatFixer.fix(self.f["live_hosts"], url_file, "url")

        wp_dir = self.f["wpscan_dir"]
        ensure_dir(wp_dir)

        token = getattr(self.p.args, "wpscan_token", None) or ""
        token_flag = f"--api-token {token}" if token else ""

        found = 0
        for url in safe_read(url_file)[:50]:
            check = self.p.shell(
                f"curl -sk --connect-timeout 5 '{url}' | grep -c 'wp-content'",
                use_tor=bool(self.p.tor)
            )
            if check.strip() and int(check.strip()) > 0:
                safe_name = url.replace("https://","").replace("http://","").replace("/","_")
                out_file  = os.path.join(wp_dir, f"{safe_name[:40]}.txt")
                self.p.shell(
                    f"wpscan --url '{url}' --enumerate vp,vt,u "
                    f"--random-user-agent {token_flag} "
                    f"--output {out_file} 2>/dev/null",
                    label=f"wpscan {url}", timeout=300
                )
                found += 1
                self.p.add_finding("medium","WORDPRESS", url, "WordPress site detected", "wpscan")
                self.p.bypass.jitter()

        self.log.success(f"WPScan done: {found} WordPress sites scanned")
