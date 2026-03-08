#!/usr/bin/env python3
# modules/step05_crawl.py — Web Crawl + JS Mining
# katana / hakrawler need: https://example.com format

import os
from core.utils import FormatFixer, count_lines

class CrawlStep:
    def __init__(self, pipeline):
        self.p   = pipeline
        self.log = pipeline.log
        self.f   = pipeline.files

    def run(self):
        # ── Auto-fix: crawlers need full URL (https://) ───────────────
        src = self.f["live_hosts"]
        if not os.path.isfile(src) or count_lines(src) == 0:
            src = self.f["subdomains"]

        url_file = self.f["fmt_url"]
        FormatFixer.fix(src, url_file, "url")   # ensure https:// prefix

        urls_out = self.f["urls"]
        threads  = self.p.args.threads

        # ── Katana — deep crawl ───────────────────────────────────────
        self.p.shell(
            f"katana -list {url_file} "
            f"-d 3 -silent -jc "
            f"-c {threads} "
            f"-H 'User-Agent: {self.p.bypass.ua()}' "
            f"2>/dev/null",
            label="katana crawl",
            append_file=urls_out,
            use_tor=bool(self.p.tor)
        )
        self.p.bypass.jitter()

        # ── Hakrawler ─────────────────────────────────────────────────
        self.p.shell(
            f"cat {url_file} | hakrawler -d 2 -t {threads} 2>/dev/null",
            label="hakrawler",
            append_file=urls_out
        )

        # ── Merge all URL sources ─────────────────────────────────────
        for extra in [self.f["wayback_urls"], self.f["gau_urls"]]:
            if os.path.isfile(extra):
                self.p.shell(f"cat {extra} >> {urls_out} 2>/dev/null")

        self.p.shell(f"sort -u {urls_out} -o {urls_out}")

        # ── Extract JS files ──────────────────────────────────────────
        js_files = self.f["js_files"]
        self.p.shell(
            f"grep -i '\\.js\\b' {urls_out} | sort -u > {js_files} 2>/dev/null"
        )

        # ── JS Secret Mining ─────────────────────────────────────────
        self._mine_js(js_files)

        # ── Arjun — parameter discovery ───────────────────────────────
        if count_lines(url_file) > 0:
            self.p.shell(
                f"arjun -i {url_file} -oT {self.f['params']} "
                f"-t {threads} -q 2>/dev/null",
                label="arjun params"
            )

        n = count_lines(urls_out)
        self.log.success(f"URLs collected: {n} → {os.path.basename(urls_out)}")

    def _mine_js(self, js_files):
        secrets_out = self.f["js_secrets"]
        SECRET_PATTERNS = (
            "api.?key|apikey|access.?token|secret.?key|client.?secret|"
            "password|passwd|private.?key|aws_|firebase|auth.?token|"
            "bearer|authorization|credential|AKIA[A-Z0-9]{16}"
        )
        self.p.shell(
            f"cat {js_files} 2>/dev/null | while read url; do "
            f"  curl -sk --connect-timeout 5 \"$url\" "
            f"  | grep -oiE '{SECRET_PATTERNS}[\"'\"'\"\\s]*[:=]+[\"'\"'\"\\s]*[^\"'\"'\"\\s{{}}]+' "
            f"  | while read m; do echo \"$url | $m\"; done; "
            f"done",
            label="JS secret mining",
            append_file=secrets_out
        )
        n = count_lines(secrets_out)
        if n > 0:
            self.p.add_finding("high", "JS_SECRETS", secrets_out,
                                f"{n} potential secrets found", "js-mining")
