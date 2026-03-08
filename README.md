# 👁 M7HUNTER v2.0

<div align="center">

```
        /\
       /  \
      /    \
     /  👁  \
    /________\
  ══════════════════════

  M7HUNTER v2.0 — Bug Bounty & Pentest Pipeline Framework
  Made by MilkyWay Intelligence  |  Author: Sharlix
```

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-red?style=flat-square&logo=linux)
![Root](https://img.shields.io/badge/Run%20As-Root%20(sudo)-critical?style=flat-square)
![License](https://img.shields.io/badge/License-M7-purple?style=flat-square)
![Tor](https://img.shields.io/badge/Tor-IP%20Rotation%20%2F%2025%20req-darkgreen?style=flat-square)

</div>

---

## ⚡ What Makes M7Hunter Different

| Feature | Details |
|---|---|
| 🔄 **True Pipeline** | Steps feed into each other — each tool gets output from previous |
| 🛠️ **Auto Format Fix** | Tool input formats fixed automatically (nmap gets bare domain, nuclei gets https://, etc.) |
| 📁 **Smart Naming** | All files prefixed with first 3 letters of domain — `exa_subdomains.txt` |
| 🌐 **Tor IP Rotation** | Auto-rotates every 25 requests via SOCKS5 |
| 🚫 **Rate Bypass** | Random UA, X-Forwarded-For spoofing, jitter delays |
| ✅ **Smart Installer** | Checks PATH + 6 common dirs before installing — never re-downloads |
| 📊 **HTML Report** | Dark-theme animated report with all findings |
| 🔁 **Resume** | Interrupted scans can be resumed with `--resume` |

---

## 🚀 Quick Start

```bash
# 1. Clone
git clone https://github.com/yourusername/m7hunter.git
cd m7hunter

# 2. One-click install (installs ALL tools)
sudo bash install.sh

# 3. Run
sudo m7hunter -u example.com --deep --tor
```

---

## 🔗 Pipeline Flow

```
Input (-u URL / -f FILE)
        │
        ▼
[1] SUBDOMAIN ENUM      subfinder + amass + crt.sh + waybackurls
        │  → exa_subdomains.txt
        ▼
[2] DNS RESOLUTION      dnsx (bare domain format auto-fixed)
        │  → exa_resolved.txt + exa_dns.txt
        ▼
[3] HTTP PROBE          httpx + gau + waybackurls (https:// auto-fixed)
        │  → exa_live_hosts.txt + exa_urls.txt
        ▼
[4] PORT SCAN           naabu + nmap (scheme stripped auto for nmap)
        │  → exa_open_ports.txt + exa_nmap.txt
        ▼
[5] CRAWL + JS MINE     katana + hakrawler + arjun + JS secret extraction
        │  → exa_urls.txt + exa_js_secrets.txt + exa_params.txt
        ▼
[6] NUCLEI              Template-based vuln scan (https:// auto-fixed)
        │  → exa_nuclei.txt
        ▼
[7] XSS                 gf → dalfox + kxss
        │  → exa_xss.txt
        ▼
[8] SQLI                gf → sqlmap
        │  → exa_sqli_params.txt
        ▼
[9] CORS                curl-based CORS misconfig check
        │  → exa_cors.txt
        ▼
[10] LFI                gf → ffuf with SecLists
        │  → exa_lfi.txt
        ▼
[11] SSRF               gf → curl AWS metadata probe
        │  → exa_ssrf.txt
        ▼
[12] OPEN REDIRECT      gf → curl redirect follow
        │  → exa_redirect.txt
        ▼
[13] TAKEOVER           subzy (bare domain auto-fixed)
        │  → exa_takeover.txt
        ▼
[14] SCREENSHOTS        gowitness (https:// auto-fixed)
        │  → screenshots/*.png
        ▼
[15] WPSCAN             WordPress detection + wpscan
        │  → wpscan/*.txt
        ▼
[16] REPORT             HTML + JSON report
           → exa_report.html + exa_findings.json
```

---

## 📁 Output Files (all prefixed with domain's first 3 letters)

```
results/exa_20260309_142501/
├── exa_raw_input.txt
├── exa_subdomains.txt       ← subfinder + amass + crt.sh
├── exa_resolved.txt         ← dnsx resolved
├── exa_dns.txt              ← MX / SPF / DMARC / NS records
├── exa_live_hosts.txt       ← httpx live hosts
├── exa_urls.txt             ← all crawled URLs
├── exa_js_files.txt         ← JS file URLs
├── exa_js_secrets.txt       ← extracted secrets from JS
├── exa_params.txt           ← arjun parameters
├── exa_open_ports.txt       ← naabu open ports
├── exa_nmap.txt             ← nmap service scan
├── exa_nuclei.txt           ← nuclei findings
├── exa_xss.txt              ← XSS findings
├── exa_sqli_params.txt      ← SQLi parameters
├── exa_cors.txt             ← CORS misconfigs
├── exa_lfi.txt              ← LFI results
├── exa_ssrf.txt             ← SSRF params
├── exa_redirect.txt         ← open redirects
├── exa_takeover.txt         ← subdomain takeover
├── exa_wayback.txt          ← waybackurls
├── exa_gau.txt              ← GAU URLs
├── exa_state.json           ← resume state
├── exa_report.html          ← 🌐 Full HTML report
├── exa_findings.json        ← All findings (JSON)
├── screenshots/             ← gowitness screenshots
└── wpscan/                  ← wpscan results
```

---

## 🔧 All Options

```bash
sudo m7hunter -h
```

### Input
| Flag | Description |
|---|---|
| `-u URL` | Single target (domain / URL / IP) |
| `-f FILE` | File with list of targets (one per line) |

### Scan Modes
| Flag | Description |
|---|---|
| `--quick` | Fast — subdomain, dns, probe, nuclei, xss, sqli, takeover |
| `--deep` | Full — all 15 steps |
| `--stealth` | Deep + Tor enabled + slow jitter |
| `--custom` | Pick individual steps manually |

### Custom Step Flags (use with `--custom`)
`--subdomain --dns --probe --ports --crawl --nuclei --xss --sqli --cors --lfi --ssrf --redirect --takeover --screenshot --wpscan`

### Options
| Flag | Description |
|---|---|
| `--tor` | Enable Tor IP rotation (rotate every 25 req) |
| `-t N` | Threads (default: 50) |
| `-o DIR` | Custom output directory |
| `--resume` | Resume interrupted scan |
| `--rate N` | Scan rate (default: 1000) |
| `--wordlist FILE` | Custom subdomain wordlist |
| `--proxy URL` | Custom proxy |
| `--install` | Install / verify all tools |
| `--no-color` | Disable terminal colors |
| `--wpscan-token` | WPScan API token |
| `--github-token` | GitHub token |

---

## 🔄 Auto Format Fixer

M7Hunter automatically converts file formats between tools:

| Tool | Needs | Auto-Fixed From |
|---|---|---|
| `dnsx` | `example.com` | strips `https://` |
| `nmap` | `example.com` | strips `https://` |
| `naabu` | `example.com` | strips `https://` |
| `nuclei` | `https://example.com` | adds `https://` |
| `katana` | `https://example.com` | adds `https://` |
| `httpx` | `example.com` | strips scheme |
| `subzy` | `example.com` | strips `https://` |
| `dalfox` | URL with params | from gf output |

---

## 🌐 Tor IP Rotation

```
Each tool call → Tor SOCKS5 (127.0.0.1:9050)
              → ProxyChains prefix for subprocess tools
              → Every 25 requests → NEWNYM signal → new circuit
              → Stealth mode: 3–8s random jitter between requests
```

Enable: `--tor` or use `--stealth` (auto-enables Tor)

---

## 📦 Auto-Installed Tools (30+)

`subfinder amass httpx nuclei naabu dnsx katana dalfox hakrawler waybackurls gau subzy gf anew gowitness ffuf kxss arjun nmap masscan sqlmap tor proxychains4 massdns wpscan curl jq git`

---

## ⚠️ Legal Disclaimer

M7Hunter is intended **ONLY** for:
- Bug bounty programs (authorized targets)
- Penetration testing with **written permission**
- Testing systems you own

**Unauthorized testing is illegal. Use responsibly.**

---

## 📜 License

M7 License — See [LICENSE](LICENSE)

---

<div align="center">
Made with ❤️ by <strong>MilkyWay Intelligence</strong> &nbsp;|&nbsp; Author: <strong>Sharlix</strong>
</div>
