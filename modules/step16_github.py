#!/usr/bin/env python3
# modules/step16_github.py — GitHub Dorking for leaked secrets
import os, urllib.request, urllib.parse, json, time

class GitHubDorkStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    DORKS = [
        "{target} password",
        "{target} secret",
        "{target} api_key",
        "{target} apikey",
        "{target} access_token",
        "{target} private_key",
        "{target} aws_access_key_id",
        "{target} database_url",
        "{target} DB_PASSWORD",
        "{target} smtp_password",
        "{target} firebase",
        "{target} .env",
        "{target} config.yml password",
        "{target} BEGIN RSA PRIVATE KEY",
        "site:{target} ext:env",
        "site:{target} ext:config",
    ]

    def run(self):
        token  = getattr(self.p.args,"github_token",None) or ""
        target = self.p.target.replace("https://","").replace("http://","").split("/")[0]
        out    = self.f["github_results"]

        if not token:
            self.log.warn("GitHub dorking: no token — rate limited (limited results)")

        found = 0
        for dork_tpl in self.DORKS:
            dork = dork_tpl.format(target=target)
            results = self._search(dork, token)
            if results:
                for item in results[:3]:
                    line = f"{dork} → {item.get('html_url','?')} [{item.get('name','?')}]"
                    with open(out,"a") as f: f.write(line+"\n")
                    found += 1
                    self.p.add_finding("high","GITHUB_EXPOSURE",
                                       item.get("html_url","?"),
                                       f"Dork: {dork[:60]}","github-dork")
            time.sleep(2 if token else 5)  # Rate limit respect

        self.log.success(f"GitHub: {found} exposed items")

    def _search(self, query, token):
        try:
            q  = urllib.parse.quote(query)
            url = f"https://api.github.com/search/code?q={q}&per_page=3"
            headers = {
                "Accept"    : "application/vnd.github.v3+json",
                "User-Agent": "M7Hunter/3.0",
            }
            if token:
                headers["Authorization"] = f"token {token}"
            req  = urllib.request.Request(url, headers=headers)
            resp = urllib.request.urlopen(req, timeout=15)
            data = json.loads(resp.read().decode())
            return data.get("items", [])
        except Exception as e:
            self.log.warn(f"GitHub search failed: {e}")
            return []
