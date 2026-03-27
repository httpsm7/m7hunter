#!/usr/bin/env python3
import random, time

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 Chrome/123.0 Mobile Safari/537.36",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "curl/8.6.0",
    "python-requests/2.31.0",
]

WAF_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Host": "localhost"},
]

class RateBypass:
    def __init__(self, min_delay=0.1, max_delay=0.8):
        self.min_d = min_delay
        self.max_d = max_delay

    def ua(self): return random.choice(UAS)

    def fake_ip(self):
        return ".".join(str(random.randint(1,254)) for _ in range(4))

    def headers(self, waf_bypass=False) -> dict:
        ip = self.fake_ip()
        h = {
            "User-Agent":       self.ua(),
            "X-Forwarded-For":  ip,
            "X-Real-IP":        ip,
            "Accept-Language":  "en-US,en;q=0.9",
            "Cache-Control":    "no-cache",
            "Accept-Encoding":  "gzip, deflate, br",
            "Connection":       "keep-alive",
        }
        if waf_bypass:
            # Add random WAF bypass header
            h.update(random.choice(WAF_BYPASS_HEADERS))
        return h

    def jitter(self):
        time.sleep(random.uniform(self.min_d, self.max_d))

    def httpx_flags(self) -> str:
        return f'-H "User-Agent: {self.ua()}" -H "X-Forwarded-For: {self.fake_ip()}"'

    def curl_flags(self, waf_bypass=False) -> str:
        h = self.headers(waf_bypass)
        return " ".join(f'-H "{k}: {v}"' for k,v in h.items())

    def ffuf_flags(self) -> str:
        return self.curl_flags()
