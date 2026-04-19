#!/usr/bin/env python3
# modules/step09_cors.py — CORS Misconfiguration Testing
# MilkyWay Intelligence | Author: Sharlix

import re
from core.utils import safe_read, count_lines
from core.http_client import sync_get

EVIL_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://evil.target.com",
]

CORS_ENDPOINTS = [
    "/api/user", "/api/me", "/api/profile", "/api/account",
    "/api/v1/user", "/api/v2/user", "/graphql",
    "/api/settings", "/api/orders", "/api/data",
]


class Step09Cors:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p    = self.p
        out  = p.files["cors_results"]
        live = p.files.get("fmt_url", "")
        urls = p.files.get("urls", "")
        found = 0

        hosts = safe_read(live)[:20]
        if not hosts:
            p.log.warn("CORS: no live hosts"); return

        p.log.info(f"CORS testing {len(hosts)} hosts")
        auth_h = {}
        if getattr(p.args, "cookie", None):
            auth_h["Cookie"] = p.args.cookie

        for host in hosts:
            host = host.rstrip("/")

            # Test common API endpoints
            test_urls = [host + ep for ep in CORS_ENDPOINTS]
            # Also test discovered URLs with params
            disc = [u for u in safe_read(urls) if host.split("//")[-1].split("/")[0] in u][:10]
            test_urls.extend(disc)

            for url in test_urls[:20]:
                for origin in EVIL_ORIGINS:
                    result = self._test_cors(url, origin, auth_h)
                    if result:
                        sev, detail = result
                        with open(out, "a") as f:
                            f.write(f"CORS: {url} | Origin:{origin} | {detail}\n")
                        p.add_finding(sev, "CORS_MISCONFIG", url, detail, "cors-engine")
                        found += 1
                        break  # one finding per URL

        p.log.success(f"CORS: {found} misconfigurations found")

    def _test_cors(self, url: str, origin: str, auth_headers: dict) -> tuple:
        headers = dict(auth_headers)
        headers["Origin"] = origin
        headers["Access-Control-Request-Method"] = "GET"

        resp = sync_get(url, headers=headers, timeout=8, follow_redirects=True)
        if not resp or resp.get("status", 0) == 0:
            return None

        acao = resp.get("headers", {}).get("access-control-allow-origin", "")
        acac = resp.get("headers", {}).get("access-control-allow-credentials", "")

        if not acao:
            return None

        # Critical: reflects evil origin + allows credentials
        if (acao == origin or acao == "*") and acac.lower() == "true":
            detail = (f"Reflects origin '{origin}' with "
                      f"Access-Control-Allow-Credentials: true — "
                      f"authenticated data theft possible")
            return ("critical", detail)

        # High: reflects arbitrary origin
        if acao == origin and origin not in ("null", "*"):
            detail = (f"Reflects arbitrary origin '{origin}' — "
                      f"cross-origin read possible (no credentials)")
            return ("high", detail)

        # Medium: wildcard
        if acao == "*":
            detail = "Wildcard CORS — public data exposed cross-origin"
            return ("low", detail)

        # Medium: null origin accepted
        if origin == "null" and acao == "null":
            detail = "null origin accepted — sandbox iframe bypass possible"
            return ("medium", detail)

        # Vary header missing (cache poisoning risk)
        vary = resp.get("headers", {}).get("vary", "")
        if acao and "origin" not in vary.lower():
            detail = f"CORS header set but Vary: Origin missing — cache poisoning risk"
            return ("low", detail)

        return None
