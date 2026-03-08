#!/usr/bin/env python3
# modules/step14_screenshot.py
import os
from core.utils import FormatFixer, ensure_dir

class ScreenshotStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        url_file = self.f["fmt_url"]
        FormatFixer.fix(self.f["live_hosts"], url_file, "url")

        ss_dir = self.f["screenshots_dir"]
        ensure_dir(ss_dir)

        self.p.shell(
            f"gowitness scan file -f {url_file} "
            f"--screenshot-path {ss_dir} "
            f"--disable-logging 2>/dev/null",
            label="gowitness screenshots", timeout=600
        )
        count = len([x for x in os.listdir(ss_dir) if x.endswith(".png")]) if os.path.isdir(ss_dir) else 0
        self.log.success(f"Screenshots: {count} → {ss_dir}/")
