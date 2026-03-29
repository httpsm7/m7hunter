#!/usr/bin/env python3
import os, re, tempfile
from core.utils import FormatFixer, count_lines

# Documentation/noise domains to skip crawling
SKIP_DOMAINS = [
    'developers.', 'docs.', 'newsroom.', 'help.',
    'support.', 'blog.', 'status.', 'careers.',
    'press.', 'legal.', 'privacy.', 'policy.',
]

class CrawlStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def _filter_urls(self, url_file: str, out_file: str) -> int:
        """Remove docs domains, placeholder URLs, example IDs from crawled URLs."""
        if not os.path.isfile(url_file): return 0
        kept = []
        with open(url_file) as f:
            for line in f:
                url = line.strip()
                if not url: continue
                # Skip documentation domains
                if any(skip in url for skip in SKIP_DOMAINS):
                    continue
                # Skip placeholder URLs like {feed_id}, {bookmark}
                if '{' in url or '}' in url:
                    continue
                # Skip obvious example/dummy params
                if re.search(r'[=&](1234567|example\.com|test@test\.com|YOUR_)' , url):
                    continue
                kept.append(url)
        # Dedup
        seen, deduped = set(), []
        for u in kept:
            if u not in seen:
                seen.add(u); deduped.append(u)
        with open(out_file, 'w') as f:
            f.write('\n'.join(deduped) + '\n')
        return len(deduped)

    def run(self):
        src = self.f["live_hosts"]
        if not os.path.isfile(src) or count_lines(src)==0: src = self.f["subdomains"]
        url_file = self.f["fmt_url"]
        FormatFixer.fix(src, url_file, "url")

        urls_out = self.f["urls"]
        threads  = self.p.args.threads
        ua       = self.p.bypass.ua()

        # katana deep crawl
        self.p.shell(
            f"katana -list {url_file} -d 3 -silent -jc -c {threads} "
            f"-H 'User-Agent: {ua}' 2>/dev/null",
            label="katana crawl", append_file=urls_out, use_tor=bool(self.p.tor))
        self.p.bypass.jitter()

        # hakrawler
        self.p.shell(f"cat {url_file} | hakrawler -d 2 -t {threads} 2>/dev/null",
                     label="hakrawler", append_file=urls_out)

        # Merge wayback + gau
        for extra in [self.f["wayback_urls"], self.f["gau_urls"]]:
            if os.path.isfile(extra):
                self.p.shell(f"cat {extra} >> {urls_out} 2>/dev/null")

        self.p.shell(f"sort -u {urls_out} -o {urls_out} 2>/dev/null")

        # Filter out docs/placeholder/example URLs (scope cleanup)
        filtered_count = self._filter_urls(urls_out, urls_out)
        self.log.info(f"  ↳ After scope filter: {filtered_count} clean URLs")

        # Extract JS files
        js_files = self.f["js_files"]
        self.p.shell(f"grep -iE '\\.js(\\?|$)' {urls_out} | sort -u > {js_files} 2>/dev/null")

        # JS secret mining — FIXED: use temp file for patterns, avoid shell escaping issues
        self._mine_js(js_files)

        # arjun param discovery
        if count_lines(url_file) > 0:
            self.p.shell(
                f"arjun -i {url_file} -oT {self.f['params']} -t {threads} -q 2>/dev/null",
                label="arjun params", timeout=600)

        n = count_lines(urls_out)
        self.log.success(f"URLs: {n} → {os.path.basename(urls_out)}")

    def _mine_js(self, js_files):
        """FIXED: Write grep pattern to file to avoid shell quote escaping issues."""
        secrets_out = self.f["js_secrets"]
        pattern_file = "/tmp/m7_js_patterns.txt"

        PATTERNS = [
            "api[_-]?key", "apikey", "access[_-]?token", "secret[_-]?key",
            "client[_-]?secret", "private[_-]?key", "aws_access", "aws_secret",
            "firebase", "auth[_-]?token", "bearer", "authorization",
            "password", "passwd", "credential", "AKIA[A-Z0-9]{16}",
            "BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY",
        ]
        with open(pattern_file,"w") as f:
            f.write("\n".join(PATTERNS)+"\n")

        # Use -f flag with pattern file — no escaping issues
        self.p.shell(
            f"cat {js_files} 2>/dev/null | while IFS= read -r url; do "
            f"  result=$(curl -sk --connect-timeout 5 --max-time 15 \"$url\" "
            f"           | grep -ioEf {pattern_file}); "
            f"  [ -n \"$result\" ] && echo \"$url | $result\"; "
            f"done",
            label="JS secret mining", append_file=secrets_out)

        # Also run trufflehog on JS if available
        self.p.shell(
            f"cat {js_files} 2>/dev/null | head -20 | while IFS= read -r url; do "
            f"  trufflehog git \"$url\" --no-update 2>/dev/null; "
            f"done",
            label="trufflehog JS", append_file=secrets_out)

        n = count_lines(secrets_out)
        if n > 0:
            self.p.add_finding("high","JS_SECRETS", secrets_out,
                                f"{n} potential secrets found", "js-mining")
