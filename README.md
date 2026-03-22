# 👁 M7Hunter v3.0 — World's #1 Bug Bounty Pipeline

```
        /\
       /  \
      /    \
     /  👁  \
    /________\
  ══════════════════════════════
  World's #1 Bug Bounty Pipeline
```

**M7Hunter v3.0** — Advanced automated bug bounty and penetration testing pipeline.  
Built from scratch. No compromises.

**Made by MilkyWay Intelligence | Author: Sharlix**

---

## ⚡ What's New in v3.0

| Feature | v2.0 | v3.0 |
|---------|------|------|
| Parallel vuln scanning | ❌ | ✅ (5x faster) |
| OOB/Interactsh blind detection | ❌ | ✅ |
| Telegram/Discord alerts | ❌ | ✅ |
| Authenticated scanning (cookie/headers) | ❌ | ✅ |
| Config file (YAML) | ❌ | ✅ |
| Continuous recon mode | ❌ | ✅ |
| GitHub dorking | ❌ | ✅ |
| Cloud asset enumeration (S3/GCP/Azure) | ❌ | ✅ |
| SSTI detection | ❌ | ✅ |
| JWT analysis + cracking | ❌ | ✅ |
| GraphQL testing | ❌ | ✅ |
| Host header injection | ❌ | ✅ |
| Adaptive timeout (no gau/amass hangs) | ❌ | ✅ |
| Filterable HTML report | ❌ | ✅ |
| Markdown report (HackerOne ready) | ❌ | ✅ |
| Scope file support | ❌ | ✅ |
| False positive deduplication | ❌ | ✅ |
| nmap/subzy bug fixed | ❌ | ✅ |
| sqlmap confirmed-only findings | ❌ | ✅ |

---

## 🚀 Quick Start

```bash
# 1. Clone
git clone https://github.com/httpsm7/m7hunter.git
cd m7hunter

# 2. Install all tools
sudo bash install.sh

# 3. Run
sudo m7hunter -u example.com --deep
```

---

## 🔧 Usage

```
sudo m7hunter -u <target> [mode] [options]
sudo m7hunter -f <targets.txt> [mode] [options]
```

### Scan Modes

| Mode | Description |
|------|-------------|
| `--quick` | Fast recon: subdomain + DNS + probe + nuclei + XSS + takeover + GitHub |
| `--deep` | Full pipeline: all 21 steps |
| `--stealth` | Deep + Tor + slow jitter |
| `--custom` | Pick steps manually |
| `--continuous` | Repeat scan on interval (default 1h) |

### Auth Options (Burp Pro style)

```bash
# Cookie-based auth
sudo m7hunter -u target.com --deep --cookie "session=abc123; csrf=xyz"

# Custom headers file
sudo m7hunter -u target.com --deep --headers headers.txt

# Basic auth
sudo m7hunter -u target.com --deep --auth admin:password
```

### Notifications

```bash
# Telegram (get critical/high findings instantly)
sudo m7hunter -u target.com --deep \
  --telegram-token 1234567890:AAB... \
  --telegram-chat -100123456789

# Discord
sudo m7hunter -u target.com --deep \
  --discord-webhook https://discord.com/api/webhooks/...
```

### API Keys

```bash
sudo m7hunter -u target.com --deep \
  --github-token ghp_xxx \
  --shodan-key xxx \
  --vt-key xxx
```

### Config File

```bash
# Copy config template
cp config/m7hunter.yaml ~/.m7hunter.yaml

# Edit with your keys
nano ~/.m7hunter.yaml

# Use
sudo m7hunter -u target.com --deep -c ~/.m7hunter.yaml
```

### Custom Steps

```bash
sudo m7hunter -u target.com --custom \
  --ssrf --xss --sqli --ssti --jwt --graphql
```

---

## 🧠 Pipeline (21 Steps)

```
Target Input
     │
     ├─ Step 01: Subdomain Enumeration (subfinder + amass + crt.sh + wayback + gau)
     ├─ Step 02: DNS Resolution (dnsx + dig records)
     ├─ Step 03: HTTP Probe (httpx + gau + waybackurls)
     ├─ Step 04: Port Scan (naabu + nmap — FIXED)
     ├─ Step 05: Web Crawl + JS Mining (katana + hakrawler + trufflehog)
     │
     ╔══════════════ PARALLEL VULN SCANNING ══════════════╗
     ║                                                      ║
     ├─ Step 06: Nuclei (custom templates + auth support)  ║
     ├─ Step 07: XSS + Blind XSS via OOB                   ║
     ├─ Step 08: SQLi (confirmed-only findings — FIXED)    ║
     ├─ Step 09: CORS Misconfiguration                     ║
     ├─ Step 10: LFI Detection                             ║
     ├─ Step 11: SSRF + OOB Blind SSRF                     ║
     ├─ Step 12: Open Redirect                             ║
     ├─ Step 13: Subdomain Takeover (subzy — FIXED)        ║
     ├─ Step 14: Screenshots (gowitness)                   ║
     ├─ Step 15: WordPress Scan                            ║
     ├─ Step 16: GitHub Dorking (leaked secrets)           ║
     ├─ Step 17: Cloud Assets (S3/GCP/Azure)               ║
     ├─ Step 18: SSTI Detection                            ║
     ├─ Step 19: JWT Analysis + Brute Force                ║
     ├─ Step 20: GraphQL Introspection                     ║
     ├─ Step 21: Host Header Injection                     ║
     ╚══════════════════════════════════════════════════════╝
     │
     └─ Report (HTML + JSON + Markdown)
```

---

## 📊 Reports

Three report formats generated automatically:

- **HTML** — Dark themed, filterable by severity, searchable
- **JSON** — Machine readable, import into your tools
- **Markdown** — HackerOne/Bugcrowd submission ready

---

## 🔎 Scanning Modules

| Module | Tools Used |
|--------|-----------|
| Subdomain | subfinder, amass, crt.sh, waybackurls, gau, dnsx |
| DNS | dnsx, dig |
| Probe | httpx, gau, waybackurls |
| Ports | naabu, nmap |
| Crawl | katana, hakrawler, arjun, trufflehog |
| Nuclei | nuclei (custom templates supported) |
| XSS | dalfox, kxss + blind XSS via Interactsh |
| SQLi | sqlmap (confirmed findings only) |
| CORS | curl |
| LFI | ffuf + direct probe |
| SSRF | gf + OOB via Interactsh + AWS/GCP/Azure probes |
| Redirect | curl + bypass payloads |
| Takeover | subzy, nuclei |
| Screenshot | gowitness |
| WordPress | wpscan |
| GitHub | GitHub API dorking |
| Cloud | S3/GCP/Azure bucket enumeration |
| SSTI | polyglot payloads (Jinja2/Twig/Freemarker/Velocity) |
| JWT | alg:none, weak secret brute, RS256→HS256 |
| GraphQL | introspection, batching |
| Host Header | injection + password reset poisoning |

---

## ⚠️ Legal Disclaimer

M7Hunter is for **authorized testing only**.

- Bug bounty programs (authorized scope)
- Penetration testing with explicit written permission
- Systems you own

Unauthorized use is illegal. You are responsible for your actions.

---

## 📜 License

M7 License v2.0 — See LICENSE file.

---

## 👨‍💻 Author

**Sharlix**  
MilkyWay Intelligence  
GitHub: [@httpsm7](https://github.com/httpsm7)

---

## ⭐ Support

⭐ Star the repo  
🐛 Report bugs  
🔧 Submit PRs
