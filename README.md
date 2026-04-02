# M7Hunter V7 🎯
### Bug Bounty Automation Framework — MilkyWay Intelligence

```
Author  : Sharlix
Handle  : httpsm7 | Sharlix | MilkyWay Intelligence
Version : 7.0
```

---

## ⚠️ Legal Disclaimer

**Authorized use only.** This tool is strictly for:
- ✔ Bug bounty programs (within scope)
- ✔ Systems you own or have explicit written permission to test
- ✔ Lab / CTF / private environments
- ❌ **Unauthorized scanning is illegal and strictly prohibited**

---

## 🆕 V7 New Features

| Feature | Description |
|---------|-------------|
| **HTTP/2** | `httpx[http2]` — multiplexed async scanning |
| **CEO Engine** | Rule-based pipeline controller: pause/resume/kill, confidence gates, auto-chain |
| **Plugin Loader** | Auto-discover engines from `plugins/`, `engines/`, `modules/` |
| **Double-Verify** | Re-confirms findings before report — eliminates ~80% false positives |
| **SPA Crawler** | Detects React/Vue/Next.js, uses Playwright headless fallback |
| **Race Engine V7** | Async HTTP/2 flood (15 simultaneous) — coupon abuse, double-spend |
| **WebSocket Engine** | WS endpoint discovery, auth bypass, injection |
| **Prototype Pollution** | Node.js `__proto__` / `constructor.prototype` testing |
| **Async Pipeline** | `asyncio.gather` for concurrent phase execution |
| **Checkpoint** | Save/resume interrupted scans |
| **Dashboard** | Live web UI at `http://localhost:8719` |

---

## 🚀 Install

```bash
sudo bash install_v7.sh
```

### Set credentials
```bash
export M7_ADMIN_USER="youruser"
export M7_ADMIN_PASS="yourpass"
echo 'export M7_ADMIN_USER="youruser"' >> ~/.bashrc
echo 'export M7_ADMIN_PASS="yourpass"' >> ~/.bashrc
```

---

## 🔧 Usage

```bash
# Basic scan
sudo m7hunter -u target.com --deep

# Authenticated scan
sudo m7hunter -u target.com --deep --cookie "session=abc123"

# Multi-session IDOR (attacker + victim)
sudo m7hunter -u target.com --deep --userA "sess_a=x" --userB "sess_b=y"

# Fast scan (Phase 1 only)
sudo m7hunter -u target.com --fast

# Stealth mode (slow, Tor-routed)
sudo m7hunter -u target.com --stealth --cookie "session=x"

# V7 specific
sudo m7hunter -u target.com --deep --ws --proto-pollution
sudo m7hunter -u target.com --deep --no-double-verify   # faster
sudo m7hunter -u target.com --deep --no-http2           # fallback

# Multiple targets
sudo m7hunter -f targets.txt --deep --cookie "session=x"

# Dashboard
sudo m7hunter --dashboard
sudo m7hunter -u target.com --deep &   # scan in background
# Open http://localhost:8719

# Telegram bot
sudo m7hunter --telegram-bot --telegram-token "BOT_TOKEN"

# Check tools
sudo m7hunter --check

# Update tools
sudo m7hunter --update
```

---

## 📋 Step Modules

| Step | Module | Vuln Type |
|------|--------|-----------|
| 01 | Subdomain Enum | subfinder, amass, crt.sh |
| 02 | DNS Resolution | dnsx, zone transfer |
| 03 | HTTP Probe | httpx, WAF detection |
| 04 | Port Scan | naabu, nmap |
| 05 | Web Crawl | katana, hakrawler, SPA |
| 06 | Nuclei | Template scan |
| 07 | XSS | dalfox, kxss |
| 08 | SQLi | sqlmap |
| 09 | CORS | Misconfiguration |
| 10 | LFI | File inclusion |
| 11 | SSRF | Server-Side Request Forgery |
| 12 | Redirect | Open Redirect + CRLF |
| 13 | Takeover | Subdomain Takeover |
| 14 | Screenshot | gowitness |
| 15 | WPScan | WordPress |
| 16 | GitHub | Secret exposure |
| 17 | Cloud | S3, GCS, Azure |
| 18 | SSTI | Template injection |
| 19 | JWT | Algorithm bypass, weak secret |
| 20 | GraphQL | Introspection, batching |
| 21 | Host Header | Injection, reset poisoning |
| 22 | IDOR | Multi-session |
| 23 | XXE | External entities |
| 24 | Smuggling | HTTP request smuggling |
| 25 | CSRF | Token/SameSite testing |
| 26 | Race | Async HTTP/2 flood |
| 27 | NoSQL | MongoDB injection |
| V7 | WebSocket | WS auth bypass, injection |
| V7 | Proto Pollution | Node.js __proto__ |

---

## 🏗️ V7 Architecture

```
M7Hunter_V7/
├── m7hunter.py              # Entry point
├── Dockerfile               # Container
├── install_v7.sh            # Installer
├── core/
│   ├── pipeline_v7.py       # Main pipeline (V7)
│   ├── ceo_engine.py        # Rule engine + live control
│   ├── plugin_loader.py     # Auto-discover plugins
│   ├── http_client.py       # HTTP/2 async client
│   ├── session_manager.py   # Multi-session auth
│   └── ...
├── engines/
│   ├── findings_engine.py   # Central registry (fixes findings=0)
│   ├── double_verify.py     # FP reduction engine
│   ├── spa_crawler.py       # Headless JS crawling
│   ├── race_engine_v7.py    # Async HTTP/2 flood
│   ├── websocket_engine.py  # WS testing
│   └── proto_pollution.py   # Prototype pollution
├── modules/
│   └── step01–step27_*.py   # All vuln step modules
├── ai/
│   ├── offline_ai.py        # Pattern-based FP filter
│   └── secure_db.py         # Brain credentials
├── confirm/
│   ├── confidence.py        # Multi-signal scoring
│   └── risk_scorer.py       # CVSS-like scoring
├── reporting/
│   └── report_generator.py  # HTML+MD+JSON+Burp XML
├── web/
│   └── dashboard.py         # Live web dashboard
└── integrations/
    └── telegram_bot.py      # Telegram control bot
```

---

## 📊 Report Formats

- **HTML** — Visual report with severity badges
- **Markdown** — Bug bounty-ready write-ups
- **JSON** — Machine-readable findings
- **Burp XML** — Import into Burp Suite

---

*M7Hunter V7 | MilkyWay Intelligence | Author: Sharlix*

