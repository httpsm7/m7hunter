#!/usr/bin/env python3
# modules/step21_host_header.py — Host Header Injection Testing
# MilkyWay Intelligence | Author: Sharlix

import re
from core.utils import safe_read
from core.http_client import sync_get

EVIL_HOSTS = [
    "evil.com",
    "evil.com:80",
    "evil.com%0d%0a",
    "evil.com:443@target.com",
    "evil.com, evil.com",
    "legitimate.com evil.com",
]

HEADERS_TO_TEST = [
    "Host",
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "Forwarded",
    "X-Original-Host",
]

INJECTION_INDICATORS = [
    r"evil\.com",
    r"password reset.*evil",
    r"<a href=[\"']https?://evil",
    r"Location:.*evil\.com",
]


class Step21HostHeader:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files["host_header_results"]
        live  = safe_read(p.files.get("fmt_url",""))[:10]
        found = 0

        if not live:
            p.log.warn("Host Header: no live hosts"); return

        p.log.info("Host Header Injection testing")
        auth_h = {}
        if getattr(p.args,"cookie",None):
            auth_h["Cookie"] = p.args.cookie

        for host in live:
            host = host.rstrip("/")

            for evil_host in EVIL_HOSTS[:4]:
                for header_name in HEADERS_TO_TEST:
                    headers = dict(auth_h)
                    headers[header_name] = evil_host

                    resp = sync_get(host, headers=headers, timeout=8,
                                    follow_redirects=True)
                    if not resp:
                        continue

                    body     = resp.get("body","")
                    location = resp.get("location","") or resp.get("headers",{}).get("location","")
                    combined = body + location

                    for pattern in INJECTION_INDICATORS:
                        if re.search(pattern, combined, re.IGNORECASE):
                            detail = (f"Host Header Injection via '{header_name}: {evil_host}' — "
                                      f"'evil.com' reflected in response/redirect")
                            with open(out,"a") as f:
                                f.write(f"HOST_HEADER_INJECTION: {host} | {detail}\n")
                            p.add_finding("high","HOST_HEADER_INJECTION",host,detail,"host-header")
                            found += 1
                            break

            # Test password reset poisoning
            reset_paths = ["/forgot-password","/reset-password","/password/reset",
                           "/api/password/reset","/auth/forgot"]
            for path in reset_paths:
                url = host + path
                resp = sync_get(url, timeout=6)
                if resp and resp.get("status",0) in (200,302):
                    # Endpoint exists - test header injection
                    headers = dict(auth_h)
                    headers["X-Forwarded-Host"] = "evil.com"
                    resp2 = sync_get(url, headers=headers, timeout=6)
                    if resp2:
                        body2 = resp2.get("body","").lower()
                        if "evil.com" in body2:
                            detail = (f"Password Reset Poisoning: X-Forwarded-Host:evil.com "
                                      f"reflected at {path} — reset links will point to evil.com")
                            p.add_finding("critical","PASSWORD_RESET_POISONING",
                                          url, detail, "host-header")
                            found += 1

        p.log.success(f"Host Header: {found} findings")
