# 👁 M7Hunter v5.0 — World's #1 Bug Bounty Pipeline

```
        /\
       /  \
      /    \
     /  👁  \
    /________\
  ══════════════════════════════════════════════════
  Dual-Phase · Confidence Scoring · Proof Engine
  OSINT Module · Telegram Bot · 108 Custom Templates
```

**M7Hunter v5.0** — Complete automated bug bounty and pentest pipeline.
Built by MilkyWay Intelligence | Author: Sharlix

---

## ⚡ What's New in v5.0

| Feature | v4.0 | v5.0 |
|---------|------|------|
| Dual-phase scan (Fast → Deep) | ❌ | ✅ |
| Confidence scoring (0.0–1.0) | ❌ | ✅ |
| Proof Engine (curl + HTTP + repro) | ❌ | ✅ |
| CVSS-like risk scoring | ❌ | ✅ |
| OSINT module (Shodan/Censys/FOFA/crt.sh) | ❌ | ✅ |
| Telegram bot control | ❌ | ✅ (full bot) |
| `--open-your-brain` data viewer | ❌ | ✅ |
| Structured audit logs (scan ID) | ❌ | ✅ |
| Custom Nuclei templates | 3 | 108 (105 new) |
| FP filtering | Pattern-based | Multi-signal + AI |

---

## 🚀 Quick Start

```bash
# 1. Install
sudo bash install.sh

# 2. Fast scan (Phase 1 only)
sudo m7hunter -u example.com --fast

# 3. Full deep scan (Phase 1 + Phase 2)
sudo m7hunter -u example.com --deep

# 4. Deep + OSINT + Proof
sudo m7hunter -u example.com --deep --osint --proof
```

---

## 🎯 Dual-Phase Architecture

### Phase 1 — Fast Scan
Lightweight signal detection. Runs these steps:
`subdomain → dns → probe → nuclei → xss → ssrf → takeover → github → idor → redirect`

**Goal:** Find suspicious endpoints quickly.

### Phase 2 — Deep Confirmation
Triggered automatically after Phase 1. Runs:
`ports → crawl → sqli → cors → lfi → screenshot → wpscan → cloud → ssti → jwt → graphql → host_header → xxe → smuggling`

**Goal:** Confirm Phase 1 findings + deep coverage.

```bash
sudo m7hunter -u target.com --deep          # Both phases
sudo m7hunter -u target.com --fast          # Phase 1 only
sudo m7hunter -u target.com --phase1-only   # Same as --fast
```

---

## 📊 Confidence Scoring Engine

Every finding gets a confidence score (0.0–1.0):

```
Signal weights:
  Confirmed pattern (root:x:, ami-id)  → +0.95–0.99
  OOB callback received                → +0.95
  Payload unencoded reflection         → +0.35
  Content-length diff >500 bytes       → +0.30
  Error signal in response             → +0.20
  Timing delay >5s (blind vulns)       → +0.40
  AI confirms                          → +0.20
  
FP weights:
  "connection refused" in SSRF         → -0.50
  HTML-encoded reflection in XSS       → -0.20
  AI marks as FP                       → -0.30

Thresholds:
  ≥ 0.85 → confirmed
  ≥ 0.50 → potential
  < 0.50 → discarded
```

```bash
sudo m7hunter -u target.com --deep --confidence 0.9  # Stricter (less noise)
sudo m7hunter -u target.com --deep --confidence 0.6  # More findings
```

---

## 🔍 Proof Engine

For every **confirmed** finding, generates:

```json
{
  "curl_command": "curl -sk ...",
  "raw_http": "GET /page?file=../etc/passwd HTTP/1.1\r\nHost: ...",
  "repro_steps": [
    "1. Open Burp Suite...",
    "2. Navigate to URL...",
    "3. Inject payload..."
  ],
  "impact": "Attacker can read arbitrary files...",
  "remediation": "Use realpath() to validate...",
  "cvss_vector": {"vector": "CVSS:3.1/AV:N/...", "score": 7.5},
  "references": ["https://portswigger.net/..."]
}
```

```bash
sudo m7hunter -u target.com --deep --proof
```

---

## 🌐 OSINT Module

```bash
sudo m7hunter -u target.com --osint

# With API keys for deeper coverage:
sudo m7hunter -u target.com --osint \
  --shodan-key YOUR_KEY \
  --censys-id YOUR_ID \
  --censys-secret YOUR_SECRET \
  --github-token ghp_xxx
```

**Sources:**
| Source | Free | Key Needed | What it finds |
|--------|------|-----------|---------------|
| crt.sh | ✅ | No | Subdomains via SSL certs |
| AlienVault OTX | ✅ | No | Passive DNS, IPs |
| URLScan.io | ✅ | No | Historical scans, URLs |
| Shodan | Partial | Yes | Exposed services, ports |
| Censys | Partial | Yes | TLS intel, hidden subdomains |
| GitHub | Partial | Token | Leaked secrets, .env files |
| VirusTotal | Partial | Yes | Passive DNS, subdomains |

**Flow:** `crt.sh → Shodan/Censys → dnsx → httpx`

---

## 📱 Telegram Bot Control

```bash
# Start bot
sudo m7hunter --telegram-bot --telegram-token TOKEN

# Available commands in Telegram:
/scan target.com --deep    # Start scan
/pause                      # Pause current scan
/resume                     # Resume scan
/stop                       # Stop scan
/status                     # Current status
/findings                   # Latest findings
/critical                   # Critical/High only
/stats                      # Statistics
/ai <question>              # Ask AI
/analyze                    # Run analysis
/check                      # Tool status
/help                       # All commands
```

---

## 🧠 Open Your Brain

View all stored intelligence data:

```bash
sudo m7hunter --open-your-brain
# Prompts for admin credentials
# Interactive menu with 9 options:
# 1. Encrypted DB contents
# 2. Scan sessions history
# 3. Pattern learning data
# 4. AI training data stats
# 5. Audit logs
# 6. Payload success rates
# 7. Top findings across all scans
# 8. Export all data to JSON
# 9. Add admin note
```

---

## 📊 Risk Scoring

CVSS-like score for every finding:

```
Score = (Exploitability × 0.30) + (Impact × 0.35) +
        (Confidence × 0.20) + (Automation × 0.15)

Severity:
  9.0-10.0 → Critical
  7.0-8.9  → High
  4.0-6.9  → Medium
  0.1-3.9  → Low

Example scores:
  SQLi confirmed by sqlmap  → 9.6 (Critical)
  SSRF AWS metadata         → 8.2 (High)
  XSS reflected             → 6.8 (Medium)
  Open Redirect             → 2.4 (Low)
```

---

## 📋 All Commands

```bash
# Scanning
sudo m7hunter -u target.com --fast             # Phase 1 only
sudo m7hunter -u target.com --deep             # Full pipeline
sudo m7hunter -u target.com --stealth --tor    # Stealth + Tor
sudo m7hunter -f targets.txt --deep            # Multiple targets
sudo m7hunter -u target.com --continuous       # Continuous mode

# V5 Features
sudo m7hunter -u target.com --deep --osint     # + OSINT
sudo m7hunter -u target.com --deep --proof     # + Proof generation
sudo m7hunter -u target.com --deep --auto-exploit  # + Auto-exploit
sudo m7hunter -u target.com --confidence 0.9   # Strict mode

# Platform
sudo m7hunter --dashboard                      # Web UI :8719
sudo m7hunter --telegram-bot                   # Bot mode
sudo m7hunter --setup-vscode                   # VS Code tasks

# Intelligence
sudo m7hunter --brain                          # Admin console
sudo m7hunter --open-your-brain                # Data viewer
sudo m7hunter --analyze                        # Upgrade report
sudo m7hunter --setup-ai                       # Install Ollama

# Tools
sudo m7hunter --install                        # Install all tools
sudo m7hunter --update                         # Update all tools
sudo m7hunter --check                          # Check versions
```

---

## 🧪 108 Custom Templates

105 new + 3 legacy = **108 total**

| Vulnerability | Templates | Strategies |
|--------------|-----------|-----------|
| SSRF | 7 | AWS metadata, OOB blind, baseline compare, POST body, IP bypass, header injection, GCP/Azure |
| XSS | 7 | Reflected HTML, attribute, DOM sinks, stored, WAF bypass, JSON API, CSP bypass |
| LFI | 7 | Unix passwd proof, encoding bypass, Windows, PHP wrappers, log poisoning, /proc/self, SSRF chain |
| SQL Injection | 7 | Error-based, boolean blind, time-based, UNION, OOB, auth bypass, second-order |
| IDOR | 7 | Numeric ID, UUID, REST API, horizontal privesc, HPP, GraphQL, JWT claim |
| XXE | 7 | Basic, blind OOB, SOAP, SVG upload, Excel, parameter entity, XInclude |
| JWT | 7 | Alg none, weak secret, RS256→HS256, no expiry, kid injection, exposure, cookie theft |
| CORS | 7 | Wildcard, reflected+creds, null origin, subdomain trust, pre-domain, HTTP, missing Vary |
| Open Redirect | 7 | Basic, bypass techniques, OAuth, javascript:, data: URI, CRLF, POST |
| SSTI | 7 | Polyglot, Jinja2 RCE, Twig RCE, Freemarker, Velocity, baseline compare, header |
| Takeover | 7 | Dangling CNAME, GitHub Pages, AWS S3, Azure, Heroku, Fastly, Shopify |
| Host Header | 7 | Basic, password reset, cache poisoning, OOB, routing bypass, absolute URL, SSRF chain |
| GraphQL | 7 | Introspection, SQLi, batch DoS, IDOR, mutations, field suggestion, depth limit |
| Command Injection | 7 | Basic, blind time, OOB, POST, JSON, file upload, headers |
| Secrets/Exposure | 7 | .env files, AWS keys, .git, Firebase, Swagger, Kubernetes, debug endpoints |

---

## ⚠️ Legal Disclaimer

M7Hunter is for **authorized testing only**.

- Bug bounty programs (authorized scope)
- Penetration testing with explicit written permission
- Systems you own

Unauthorized use is illegal. You are responsible.

---

## 📜 License

M7 License v2.0 — See LICENSE file.

## 👨‍💻 Author

**Sharlix** | MilkyWay Intelligence | [@httpsm7](https://github.com/httpsm7)
