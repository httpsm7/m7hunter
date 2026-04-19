<div align="center">

```
███╗   ███╗███████╗██╗  ██╗██╗   ██╗███╗  ██╗████████╗███████╗██████╗
████╗ ████║╚════██║██║  ██║██║   ██║████╗ ██║╚══██╔══╝██╔════╝██╔══██╗
██╔████╔██║    ██╔╝███████║██║   ██║██╔██╗██║   ██║   █████╗  ██████╔╝
██║╚██╔╝██║   ██╔╝ ██╔══██║╚██╗ ██╔╝██║╚████║   ██║   ██╔══╝  ██╔══██╗
██║ ╚═╝ ██║   ██║  ██║  ██║ ╚████╔╝ ██║ ╚███║   ██║   ███████╗██║  ██║
╚═╝     ╚═╝   ╚═╝  ╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

# M7Hunter — Bug Bounty Automation Framework

**The most complete Python-based bug bounty automation tool with AI-powered analysis**

[![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python)](https://python.org)
[![Version](https://img.shields.io/badge/Version-V7-cyan?style=flat-square)](https://github.com/httpsm7/m7hunter)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-red?style=flat-square&logo=linux)](https://kali.org)
[![Author](https://img.shields.io/badge/Author-Sharlix-purple?style=flat-square)](https://github.com/httpsm7)
[![Brand](https://img.shields.io/badge/Brand-MilkyWay%20Intelligence-blue?style=flat-square)](https://github.com/httpsm7)

**Author:** [Sharlix](https://github.com/httpsm7) | **Brand:** MilkyWay Intelligence | **Handle:** httpsm7

</div>

---

## ⚠️ Legal Disclaimer — Authorized Use Only

> **M7Hunter is strictly for authorized security testing. Unauthorized use is ILLEGAL.**

✅ **Allowed:** Bug Bounty Programs (within scope) · Systems you own · Lab/CTF environments · Authorized pentests

❌ **Prohibited:** Unauthorized scanning · Any illegal activity

> By using M7Hunter, you accept full legal responsibility.

---

## What is M7Hunter?

M7Hunter is a **full-stack bug bounty automation framework** that automates the entire vulnerability discovery pipeline — from subdomain enumeration to exploit confirmation to report generation.

**Unlike other scanners, M7Hunter:**
- Doesn't just detect — it **confirms** vulnerabilities with double-verification
- Doesn't just list bugs — it shows **exploit paths and impact**
- **Chains vulnerabilities** automatically (IDOR→ATO, SSRF→Cloud, XSS→Session)
- Has a **CEO Rule Engine** for real-time scan control
- Generates **bug-bounty-ready reports** (HTML, Markdown, JSON, Burp XML)
- **V7 only:** Local Ollama AI chatbot that knows all your findings and can explain how to exploit them

---

## Version History — V1 to V7

### V1 — Basic Recon — Score: 2/10
- Subfinder subdomain enum only
- Static text output
- No vuln testing, no reports, single-threaded

### V2 — First Vulns — Score: 3/10
- Added Nuclei, dalfox, nmap
- Simple HTML report
- High false positive rate, no confirmation

### V3 — Multi-Phase Pipeline — Score: 4/10
- Dual-phase pipeline (Recon → Vuln)
- 13 automated steps
- SQLi, LFI, SSRF basic testing
- Findings=0 bug existed

### V4 — AI Layer — Score: 4.5/10
- Offline AI pattern engine
- Brain/CEO concept
- Telegram bot
- Multi-threading (6 workers)
- **Critical bugs:** Hardcoded credentials, SSRF missed params, wrong sqlmap parser

### V5 — Exploitation Focus — Score: 5.5/10
- Exploit engine
- Confidence scoring
- Tor IP rotation, WAF evasion
- 20+ step modules
- **Still broken:** Race conditions in observer, scope never enforced, smuggler path hardcoded

### V6 — Major Bug Fix Release — Score: 7/10

**47 bugs fixed:**

| Bug | Fix |
|-----|-----|
| Hardcoded credentials | Moved to env vars (M7_ADMIN_USER / M7_ADMIN_PASS) |
| SSRF missed params | Python urllib.parse — tests ALL params |
| SQLmap parser wrong | Fixed to actual sqlmap output string |
| 4500 LFI false positives | Added file content verification |
| 148 IDOR false positives | Added personal data pattern verification |
| GitHub 401 spam | Skip when no token |
| S3 403 = false positive | Fixed: 403 = no finding |
| Observer race conditions | Added threading locks |
| suspicious_endpoints O(n) | Changed list → set |
| Smuggler path hardcoded | Auto-find + auto-install |
| CEO 0-line warnings | Fixed output file mapping |
| Scope not enforced | is_in_scope() now called |

**New in V6:** CSRF, Race Conditions, NoSQL injection, multi-session IDOR, Burp XML export

### V7 — Complete Professional Framework — Score: 8.5/10

**Ground-up redesign with professional architecture.**

| Component | Description |
|-----------|-------------|
| Plugin Loader | Auto-discovers modules — hot-reload support |
| CEO Engine | pause/resume/kill, confidence gates, auto-chain |
| HTTP/2 Client | httpx async HTTP/2, connection pooling, flood mode |
| Async Pipeline | asyncio + ThreadPoolExecutor — parallel phases |
| FindingsEngine | Thread-safe registry — FIXED Findings=0 permanently |
| DoubleVerify | Re-confirms every finding — 80% fewer false positives |
| Checkpoint/Resume | Save and resume interrupted scans |
| SPA Crawler | Playwright headless for React/Vue/Next.js |
| Race Engine V7 | 15 simultaneous HTTP/2 requests |
| WebSocket Engine | WS auth bypass, injection testing |
| Prototype Pollution | Node.js \_\_proto\_\_ testing |
| OOB Detection | Interactsh blind SSRF/XXE callbacks |
| Dashboard | Live web UI at localhost:8719 |
| Ollama AI | Local LLM chatbot with full scan context |

---

## Version Comparison

| Feature | V1 | V2 | V3 | V4 | V5 | V6 | V7 |
|---------|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Subdomain Enum | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| XSS | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅++ |
| SQLi | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SSRF | ❌ | ❌ | ✅ | ✅ | ✅ | ✅++ | ✅++ |
| LFI | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| IDOR | ❌ | ❌ | ❌ | ✅ | ✅ | ✅++ | ✅++ |
| CSRF | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Race Conditions | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅++ |
| NoSQL Injection | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| SSTI | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| JWT Testing | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| GraphQL | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| WebSocket | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| XXE | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Host Header | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Prototype Pollution | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| HTTP Smuggling | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| Subdomain Takeover | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| Tor Rotation | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| Multi-Session | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Double-Verify FP | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| HTTP/2 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| SPA/JS Crawl | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| CEO Engine | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| OOB Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Burp XML Export | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Dashboard | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Ollama AI | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Docker | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Score** | **2/10** | **3/10** | **4/10** | **4.5/10** | **5.5/10** | **7/10** | **8.5/10** |

---

## Installation

```bash
git clone https://github.com/httpsm7/m7hunter.git
cd m7hunter
sudo bash install_v8.sh
```

**Set credentials:**
```bash
export M7_ADMIN_USER="yourusername"
export M7_ADMIN_PASS="yourpassword"
echo 'export M7_ADMIN_USER="yourusername"' >> ~/.bashrc
echo 'export M7_ADMIN_PASS="yourpassword"' >> ~/.bashrc
```

**Verify:**
```bash
m7hunter --check
```

---

## Usage

```bash
# Basic deep scan
sudo m7hunter -u target.com --deep

# Authenticated scan
sudo m7hunter -u target.com --deep --cookie "session=abc123"

# Multi-session IDOR
sudo m7hunter -u target.com --deep \
  --userA "session=attacker_token" \
  --userB "session=victim_token"

# Fast scan
sudo m7hunter -u target.com --fast

# Stealth (Tor-routed)
sudo m7hunter -u target.com --stealth

# Multiple targets
sudo m7hunter -f targets.txt --deep

# Live dashboard
sudo m7hunter --dashboard
# Open: http://localhost:8719

# Telegram alerts
sudo m7hunter -u target.com --deep \
  --telegram-token "TOKEN" --telegram-chat "CHAT_ID"

# V7 features
sudo m7hunter -u target.com --deep --ws --proto-pollution
sudo m7hunter -u target.com --deep --no-double-verify --confidence 0.7
sudo m7hunter -u target.com --deep --resume
```

---

## Vulnerability Coverage (30+ Types)

**Injection:** SQLi · NoSQL · SSTI · XXE · LFI · CRLF · Header Injection

**Authentication:** JWT bypass · Weak secrets · OAuth redirect

**Authorization:** IDOR · Mass Assignment · Privilege Escalation

**Client-Side:** XSS (Reflected/Stored/DOM/Blind) · CSRF

**Business Logic:** Race Conditions · Coupon Abuse · Double-Spend

**Infrastructure:** SSRF (Cloud Metadata) · Subdomain Takeover · Open Ports

**Cloud:** S3 Open Buckets · GCS · Azure Blob · Firebase

**Modern Web:** GraphQL Introspection · WebSocket Auth Bypass · Prototype Pollution

**Network:** HTTP Request Smuggling · Host Header Injection

**Secrets:** GitHub exposure · JS secrets · API key leakage

---

## Attack Chains (Auto-Suggested)

```
IDOR        → Change victim email → Password reset → Account Takeover
SSRF        → AWS metadata → IAM credentials → Cloud compromise  
Open Redirect → OAuth bypass → Access token theft
LFI         → /proc/self/environ → Log poisoning → RCE
CORS + XSS  → Cross-origin credential theft
Host Header → Password Reset Poisoning → Account Takeover
JWT alg:none → Forge admin token → Privilege escalation
```

---

## Project Structure

```
M7Hunter/
├── m7hunter.py              ← Entry point
├── Dockerfile               ← Container deployment
├── install_v8.sh            ← Installer
├── core/                    ← Pipeline, CEO Engine, HTTP/2
│   ├── pipeline_v7.py       ← Async plugin-driven pipeline
│   ├── ceo_engine.py        ← Real-time scan control
│   ├── http_client.py       ← HTTP/2 async client
│   └── plugin_loader.py     ← Auto-discover modules
├── engines/                 ← 12 Specialized Engines
│   ├── findings_engine.py   ← Central thread-safe registry
│   ├── double_verify.py     ← False-positive reduction
│   ├── spa_crawler.py       ← Playwright headless crawl
│   ├── race_engine_v7.py    ← Async HTTP/2 flood
│   └── websocket_engine.py  ← WebSocket testing
├── modules/                 ← 27 Step Modules (step01-step27)
├── ai/                      ← Offline AI + Brain
├── reporting/               ← HTML + MD + JSON + Burp XML
├── web/                     ← Live Dashboard + REST API
│   └── static/index.html    ← Full dynamic web UI
└── integrations/            ← Telegram Bot + Ollama AI
```

---

## Platforms

HackerOne · Bugcrowd · Intigriti · YesWeHack · OpenBugBounty · Synack

---

## Author

**Sharlix** — Bug Bounty Hunter | Security Researcher

- GitHub: [@httpsm7](https://github.com/httpsm7)
- Brand: **MilkyWay Intelligence**
- Platforms: HackerOne · Bugcrowd · Intigriti · YesWeHack · OpenBugBounty

---

## Keywords

`bug bounty automation` `web application security scanner` `vulnerability scanner python` `penetration testing automation` `IDOR testing tool` `XSS scanner automation` `SSRF detection` `SQLi automation` `subdomain enumeration tool` `bug bounty tool kali linux` `automated recon` `python security tool` `offensive security automation` `ethical hacking framework` `vulnerability assessment tool` `security automation python` `OWASP testing automation` `hackerone automation` `bugcrowd automation`

---

<div align="center">

**For authorized security testing only. Always get written permission before testing.**

Made by [Sharlix](https://github.com/httpsm7) | MilkyWay Intelligence

</div>
