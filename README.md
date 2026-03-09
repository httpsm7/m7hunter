# 👁 M7Hunter v2.0

### Advanced Bug Bounty & Penetration Testing Pipeline Framework

```
        /\
       /  \
      /    \
     /  👁  \
    /______\
══════════════════════
```

**M7Hunter v2.0** is an advanced **reconnaissance and vulnerability scanning pipeline** designed for **bug bounty hunters, penetration testers, and security researchers**.

Developed by **MilkyWay Intelligence**
Author: **Sharlix**

M7Hunter automates the **entire attack surface discovery process** by chaining multiple security tools into a **true pipeline workflow**.

---

# ⚡ Key Features

| Feature                    | Description                                               |
| -------------------------- | --------------------------------------------------------- |
| 🔄 True Pipeline           | Each phase feeds results into the next tool automatically |
| 🛠 Smart Input Formatter   | Automatically converts formats between tools              |
| 📁 Intelligent File Naming | Output files prefixed with domain identifier              |
| 🌐 Tor IP Rotation         | Automatic Tor circuit rotation for stealth scanning       |
| 🚫 Rate Bypass             | Random user-agents and spoofed headers                    |
| 📊 HTML Security Report    | Dark themed animated vulnerability report                 |
| 🔁 Resume Mode             | Resume interrupted scans anytime                          |
| ⚙️ Smart Installer         | Installs missing tools automatically                      |

---

# 🧠 Recon Pipeline

```
Target Input
     │
     ▼
Subdomain Enumeration
     │
     ▼
DNS Resolution
     │
     ▼
Live Host Detection
     │
     ▼
Port Scanning
     │
     ▼
Web Crawling & JS Mining
     │
     ▼
Vulnerability Scanning
     │
     ▼
Automated Security Report
```

---

# 🔎 Scanning Modules

M7Hunter integrates multiple security scanning modules:

| Module                | Tools                    |
| --------------------- | ------------------------ |
| Subdomain Enumeration | subfinder, amass, crt.sh |
| DNS Resolution        | dnsx                     |
| HTTP Probing          | httpx                    |
| Port Scanning         | naabu, nmap              |
| Crawler               | katana, hakrawler        |
| Parameter Discovery   | arjun                    |
| Vulnerability Scan    | nuclei                   |
| XSS Detection         | dalfox, kxss             |
| SQL Injection         | sqlmap                   |
| CORS Testing          | curl                     |
| LFI Detection         | ffuf                     |
| SSRF Testing          | AWS metadata probes      |
| Open Redirect         | curl redirect checks     |
| Subdomain Takeover    | subzy                    |
| Screenshots           | gowitness                |
| WordPress Scan        | wpscan                   |

---

# 🚀 Quick Start

### 1️⃣ Clone Repository

```
git clone https://github.com/yourusername/m7hunter.git
cd m7hunter
```

### 2️⃣ Install Tools

```
sudo bash install.sh
```

### 3️⃣ Run Scan

```
sudo m7hunter -u example.com --deep --tor
```

---

# 📂 Output Structure

Example scan output:

```
results/exa_20260309_142501/

├── exa_subdomains.txt
├── exa_resolved.txt
├── exa_dns.txt
├── exa_live_hosts.txt
├── exa_urls.txt
├── exa_js_files.txt
├── exa_js_secrets.txt
├── exa_params.txt
├── exa_open_ports.txt
├── exa_nmap.txt
├── exa_nuclei.txt
├── exa_xss.txt
├── exa_sqli_params.txt
├── exa_cors.txt
├── exa_lfi.txt
├── exa_ssrf.txt
├── exa_redirect.txt
├── exa_takeover.txt
├── exa_wayback.txt
├── exa_gau.txt
├── exa_report.html
├── exa_findings.json
├── screenshots/
└── wpscan/
```

---

# 🛠 CLI Usage

```
sudo m7hunter -h
```

### Target Input

| Flag | Description          |
| ---- | -------------------- |
| -u   | Scan single target   |
| -f   | Scan list of targets |

---

# ⚙ Scan Modes

| Mode      | Description                 |
| --------- | --------------------------- |
| --quick   | Fast reconnaissance scan    |
| --deep    | Full vulnerability pipeline |
| --stealth | Deep scan with Tor + jitter |
| --custom  | Select modules manually     |

---

# 🔧 Custom Scan Modules

```
--subdomain
--dns
--probe
--ports
--crawl
--nuclei
--xss
--sqli
--cors
--lfi
--ssrf
--redirect
--takeover
--screenshot
--wpscan
```

---

# 🌐 Tor Stealth Mode

M7Hunter supports automatic **Tor proxy routing** for stealth scanning.

Features include:

* SOCKS5 proxy support
* Automatic IP rotation
* Circuit refresh every 25 requests
* Random request delays

Enable with:

```
--tor
```

or

```
--stealth
```

---

# 📦 Tools Installed Automatically

M7Hunter installs and manages over **30 reconnaissance tools** including:

* subfinder
* amass
* httpx
* nuclei
* naabu
* dnsx
* katana
* dalfox
* hakrawler
* waybackurls
* gau
* subzy
* gf
* ffuf
* arjun
* sqlmap
* nmap
* masscan
* gowitness
* tor
* proxychains

---

# 📊 Automated Report

M7Hunter generates:

* 🌐 HTML interactive report
* 📁 JSON findings export
* 📸 Screenshots of discovered hosts
* 📋 Vulnerability classification

Report includes:

* Attack surface overview
* Subdomain inventory
* Open ports
* Vulnerability findings
* Severity categorization

---

# ⚠️ Legal Disclaimer

M7Hunter is intended **only for authorized security testing**.

Allowed usage:

* Bug bounty programs
* Authorized penetration testing
* Testing infrastructure you own

Unauthorized scanning may violate laws and regulations.

Use responsibly.

---

# 📜 License

M7 License

See **LICENSE** file for details.

---

# 👨‍💻 Author

**Sharlix**
MilkyWay Intelligence

---

# ⭐ Support the Project

If you find M7Hunter useful:

⭐ Star the repository
🐛 Report bugs
🔧 Contribute improvements

---

# 🔎 Keywords

Bug bounty tools, reconnaissance framework, penetration testing automation, vulnerability scanner, cybersecurity toolkit, security research tools, subdomain enumeration, nuclei scanner pipeline.


