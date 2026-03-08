#!/usr/bin/env python3
# core/rate_bypass.py

import random, time

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/122.0.0.0 Mobile Safari/537.36",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
]

class RateBypass:
    def __init__(self, min_delay=0.3, max_delay=1.5):
        self.min_d = min_delay
        self.max_d = max_delay

    def ua(self): return random.choice(UAS)

    def fake_ip(self):
        return ".".join(str(random.randint(1,254)) for _ in range(4))

    def headers(self) -> dict:
        ip = self.fake_ip()
        return {
            "User-Agent":       self.ua(),
            "X-Forwarded-For":  ip,
            "X-Real-IP":        ip,
            "X-Originating-IP": ip,
            "X-Client-IP":      ip,
            "CF-Connecting-IP": ip,
            "True-Client-IP":   ip,
            "Accept-Language":  "en-US,en;q=0.9",
            "Cache-Control":    "no-cache",
        }

    def jitter(self):
        time.sleep(random.uniform(self.min_d, self.max_d))

    def httpx_flags(self) -> list:
        return ["-H", f"User-Agent: {self.ua()}",
                "-H", f"X-Forwarded-For: {self.fake_ip()}"]

    def ffuf_flags(self) -> str:
        h = self.headers()
        return " ".join(f'-H "{k}: {v}"' for k, v in h.items())
