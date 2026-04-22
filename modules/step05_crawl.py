#!/usr/bin/env python3
# modules/step05_crawl.py — Web Crawl + Parameter Extraction
# V7: SPA detection + headless fallback via SPACrawler
# MilkyWay Intelligence | Author: Sharlix

import asyncio, os
from core.utils import count_lines, safe_read


class Step05Crawl:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p   = self.p
        live = p.files["live_hosts"]
        out  = p.files["urls"]
        js   = p.files["js_files"]
        par  = p.files["params"]
        t    = p.tmgr.get

        hosts = safe_read(p.files.get("fmt_url","")) or safe_read(live)
        if not hosts:
            tgt = p.target if p.target.startswith("http") else "https://" + p.target
            hosts = [tgt]
        hosts = hosts[:20]

        cookie_flag = f'--header "Cookie: {p.args.cookie}"' if getattr(p.args,"cookie",None) else ""
        p.log.info(f"Crawling {len(hosts)} hosts (V7: SPA-aware)")

        # Waybackurls
        tgt_domain = p.target.replace("https://","").replace("http://","").split("/")[0]
        p.shell(
            f"waybackurls {tgt_domain} 2>/dev/null",
            label="waybackurls", tool_name="waybackurls",
            append_file=out, timeout=t("waybackurls")
        )

        # gau
        p.shell(
            f"gau --threads 5 --subs {tgt_domain} 2>/dev/null",
            label="gau", tool_name="gau",
            append_file=out, timeout=t("gau")
        )

        # katana (fast JS crawl)
        for host in hosts[:10]:
            p.shell(
                f"katana -u {host} -silent -d 3 -jc -kf all "
                f"-ef png,jpg,gif,svg,woff,ttf,css "
                f"-H 'Cookie:{p.args.cookie}' 2>/dev/null" if getattr(p.args,"cookie",None) else
                f"katana -u {host} -silent -d 3 -jc -kf all "
                f"-ef png,jpg,gif,svg,woff,ttf,css 2>/dev/null",
                label=f"katana {host[:40]}", tool_name="katana",
                append_file=out, timeout=t("katana")
            )

        # hakrawler
        for host in hosts[:5]:
            p.shell(
                f"echo {host} | hakrawler -d 3 -subs 2>/dev/null",
                label=f"hakrawler {host[:40]}", tool_name="hakrawler",
                append_file=out, timeout=t("hakrawler")
            )

        # V7: SPA crawl for React/Vue/Angular apps
        try:
            import asyncio as _asyncio
            _loop = _asyncio.new_event_loop()
            _loop.run_until_complete(self._spa_crawl(hosts[:5], out))
            _loop.close()
        except Exception as _spa_err:
            p.log.warn(f"SPA crawl: {_spa_err}")
        except Exception as e:
            p.log.warn(f"SPA crawl error: {e}")

        # Extract JS files
        p.shell(
            f"grep -E '\\.js(\\?|$)' {out} 2>/dev/null | sort -u",
            label="js files", append_file=js, timeout=30
        )

        # Parameter extraction (arjun / gf)
        p.shell(
            f"cat {out} 2>/dev/null | grep '?' | sort -u | "
            f"gf xss gf sqli gf ssrf gf redirect gf lfi 2>/dev/null | sort -u",
            label="gf param extract", append_file=par, timeout=60
        )
        p.shell(
            f"cat {out} 2>/dev/null | grep '?' | sort -u | head -50",
            label="raw params", append_file=par, timeout=20
        )

        # Dedup
        p.shell(f"sort -u {out} -o {out} 2>/dev/null", timeout=10)
        p.shell(f"sort -u {par} -o {par} 2>/dev/null", timeout=10)

        n_urls   = count_lines(out)
        n_params = count_lines(par)
        p.log.success(f"URLs: {n_urls} | Params: {n_params}")

    async def _spa_crawl(self, hosts, out):
        """V7: SPA/headless crawl for JS-heavy apps."""
        crawler = self.p.spa_crawler
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
                            f"{len(urls)} endpoints found for {host[:40]}"
                        )
            except Exception:
                pass
