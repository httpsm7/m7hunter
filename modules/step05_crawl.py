#!/usr/bin/env python3
# modules/step05_crawl.py — Web Crawl + Parameter Extraction (FIXED)
# BUG-001 FIX: gf command syntax corrected (separate per pattern)
# BUG-003 FIX: SPA crawl indentation fixed
# BUG-007 FIX: hakrawler 5→50 hosts
# BUG-008 FIX: fallback params 50→1000
# BUG-017 FIX: katana cookie flag cleaned up
# MilkyWay Intelligence | Author: Sharlix

import os
from core.utils import count_lines, safe_read
from core.error_handler import get_handler


class Step05Crawl:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p    = self.p
        live = p.files["live_hosts"]
        out  = p.files["urls"]
        js   = p.files["js_files"]
        par  = p.files["params"]
        t    = p.tmgr.get

        # Build host list with fallback chain
        hosts = safe_read(p.files.get("fmt_url", ""))
        if not hosts:
            hosts = safe_read(live)
        if not hosts:
            tgt = p.target if p.target.startswith("http") else "https://" + p.target
            hosts = [tgt]
        hosts = hosts[:100]

        tgt_domain = p.target.replace("https://","").replace("http://","").split("/")[0]
        cookie_h   = f'Cookie: {p.args.cookie}' if getattr(p.args,"cookie",None) else ""

        p.log.info(f"Crawling {len(hosts)} hosts")

        # ── Waybackurls ───────────────────────────────────────────────
        p.shell(
            f"waybackurls {tgt_domain} 2>/dev/null",
            label="waybackurls", append_file=out, timeout=t("waybackurls")
        )

        # ── gau ───────────────────────────────────────────────────────
        p.shell(
            f"gau --threads 5 --subs {tgt_domain} 2>/dev/null",
            label="gau", append_file=out, timeout=t("gau")
        )

        # ── katana ────────────────────────────────────────────────────
        for host in hosts[:50]:
            host = host.strip()
            base_cmd = (
                f"katana -u {host} -silent -d 3 -jc -kf all "
                f"-ef png,jpg,gif,svg,woff,ttf,css 2>/dev/null"
            )
            if cookie_h:
                base_cmd = (
                    f"katana -u {host} -silent -d 3 -jc -kf all "
                    f"-ef png,jpg,gif,svg,woff,ttf,css "
                    f"-H '{cookie_h}' 2>/dev/null"
                )
            p.shell(base_cmd, label=f"katana {host[:40]}",
                    append_file=out, timeout=t("katana"))

        # ── hakrawler — BUG-007 FIX: 5→50 hosts ─────────────────────
        for host in hosts[:50]:
            host = host.strip()
            p.shell(
                f"echo {host} | hakrawler -d 3 -subs 2>/dev/null",
                label=f"hakrawler {host[:40]}", append_file=out,
                timeout=t("hakrawler")
            )

        # ── SPA crawl ─────────────────────────────────────────────────
        try:
            import asyncio as _asyncio
            _loop = _asyncio.new_event_loop()
            _loop.run_until_complete(self._spa_crawl(hosts[:5], out))
            _loop.close()
        except Exception as _spa_err:
            # BUG-003 FIX: properly inside except block
            get_handler().capture("step05_crawl", _spa_err, "_spa_crawl")
            p.log.warn(f"SPA crawl: {_spa_err}")

        # ── JS file extraction ────────────────────────────────────────
        p.shell(
            f"grep -E '\\.js(\\?|$)' {out} 2>/dev/null | sort -u",
            label="js files", append_file=js, timeout=30
        )

        # ── Parameter extraction — BUG-001 FIX: gf per pattern ───────
        gf_patterns = ["xss","sqli","ssrf","redirect","lfi","rce","ssti","idor"]
        gf_ok = os.path.isdir(os.path.expanduser("~/.gf"))

        if gf_ok:
            for pattern in gf_patterns:
                p.shell(
                    f"cat {out} 2>/dev/null | gf {pattern} 2>/dev/null",
                    label=f"gf {pattern}", append_file=par, timeout=30
                )
        else:
            p.log.warn("gf patterns not installed — using raw URL extraction")

        # ── BUG-008 FIX: fallback 50→1000 raw params ─────────────────
        p.shell(
            f"cat {out} 2>/dev/null | grep '?' | sort -u | head -1000",
            label="raw params", append_file=par, timeout=20
        )

        # Dedup
        p.shell(f"sort -u {out} -o {out} 2>/dev/null", timeout=10)
        p.shell(f"sort -u {par} -o {par} 2>/dev/null", timeout=10)

        n_urls   = count_lines(out)
        n_params = count_lines(par)
        p.log.success(f"URLs: {n_urls} | Params: {n_params}")

    async def _spa_crawl(self, hosts, out):
        """SPA/headless crawl for JS-heavy apps."""
        try:
            crawler = self.p.spa_crawler
        except AttributeError:
            return
        for host in hosts:
            try:
                urls = await crawler.crawl(host, depth=2)
                if urls:
                    with open(out, "a") as f:
                        for u in urls:
                            if u.startswith("http"):
                                f.write(u + "\n")
                    spa_info = crawler.detect_spa("")
                    if spa_info.get("is_spa"):
                        self.p.log.info(
                            f"  SPA ({spa_info['framework']}): "
                            f"{len(urls)} endpoints — {host[:40]}"
                        )
            except Exception as _e:
                get_handler().capture("step05_crawl", _e, f"spa:{host}")
