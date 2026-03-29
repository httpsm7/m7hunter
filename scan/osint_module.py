#!/usr/bin/env python3
# scan/osint_module.py — M7Hunter v5.0 OSINT Intelligence Module
# Shodan | Censys | FOFA | ZoomEye | crt.sh | GitHub | Google Dorks
# MilkyWay Intelligence | Author: Sharlix

import os
import json
import time
import urllib.request
import urllib.parse
import urllib.error
import re

R="\033[91m"; B="\033[34m"; C="\033[96m"; Y="\033[93m"
G="\033[92m"; W="\033[97m"; DIM="\033[2m"; RST="\033[0m"; BOLD="\033[1m"


class OSINTModule:
    """
    V5 OSINT Module — collects intelligence from multiple sources.

    Sources:
    1. crt.sh         — subdomain discovery via SSL certificates (free)
    2. Shodan         — exposed services (API key optional)
    3. Censys         — TLS intel + hidden subdomains (API key optional)
    4. FOFA           — banner/header discovery (API key optional)
    5. GitHub         — leaked secrets, source code (API key optional)
    6. URLScan.io     — browser screenshots, URLs (free)
    7. VirusTotal     — passive DNS, subdomains (API key optional)
    8. AlienVault OTX — threat intel, IPs (free)
    9. ThreatCrowd    — historical DNS (free)

    Flow: crt.sh → Shodan/Censys → dnsx → httpx
    """

    def __init__(self, target: str, pipeline, log=None):
        self.target  = target.strip().replace("https://","").replace("http://","").split("/")[0]
        self.pipeline= pipeline
        self.log     = log or (pipeline.log if pipeline else None)
        self.cfg     = pipeline.cfg if pipeline else None
        self.out     = pipeline.out if pipeline else "/tmp"
        self.results = {
            "subdomains"     : set(),
            "ips"            : set(),
            "services"       : [],
            "exposed_ports"  : [],
            "leaked_files"   : [],
            "certificates"   : [],
            "urls_found"     : [],
        }

    # ── Main runner ──────────────────────────────────────────────────
    def run(self) -> dict:
        self._info(f"OSINT scan: {self.target}")
        print()

        # Free sources first (no key needed)
        self._run_crtsh()
        self._run_alienvault()
        self._run_urlscan()

        # API-based (if key provided)
        if self._get_key("shodan_key"):
            self._run_shodan()
        else:
            self._warn("Shodan: no API key — skipping")

        if self._get_key("censys_id") and self._get_key("censys_secret"):
            self._run_censys()
        else:
            self._warn("Censys: no API key — skipping")

        if self._get_key("github_token"):
            self._run_github_osint()
        else:
            self._warn("GitHub: no token — limited OSINT")

        if self._get_key("vt_key"):
            self._run_virustotal()
        else:
            self._warn("VirusTotal: no API key — skipping")

        # Save results
        self._save()
        self._print_summary()
        return self.results

    # ── crt.sh ───────────────────────────────────────────────────────
    def _run_crtsh(self):
        self._info("crt.sh → SSL certificate transparency")
        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            req = urllib.request.Request(
                url, headers={"User-Agent": "M7Hunter/5.0"})
            resp = urllib.request.urlopen(req, timeout=30)
            data = json.loads(resp.read().decode())
            found = set()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().replace("*.", "")
                    if sub.endswith(f".{self.target}") or sub == self.target:
                        found.add(sub)
            self.results["subdomains"].update(found)
            self._success(f"crt.sh: {len(found)} subdomains found")
            # Also extract SANs from certificates
            for entry in data[:50]:
                san = entry.get("name_value","")
                issuer = entry.get("issuer_name","")
                if san:
                    self.results["certificates"].append({
                        "san"    : san,
                        "issuer" : issuer,
                        "logged" : entry.get("entry_timestamp",""),
                    })
        except Exception as e:
            self._warn(f"crt.sh failed: {e}")

    # ── AlienVault OTX ───────────────────────────────────────────────
    def _run_alienvault(self):
        self._info("AlienVault OTX → passive DNS + threat intel")
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.target}/passive_dns"
            req = urllib.request.Request(
                url, headers={"User-Agent": "M7Hunter/5.0"})
            resp = urllib.request.urlopen(req, timeout=20)
            data = json.loads(resp.read().decode())
            for record in data.get("passive_dns", []):
                hostname = record.get("hostname","")
                address  = record.get("address","")
                if hostname.endswith(f".{self.target}"):
                    self.results["subdomains"].add(hostname)
                if address and re.match(r'^\d+\.\d+\.\d+\.\d+$', address):
                    self.results["ips"].add(address)
            self._success(f"AlienVault: {len(data.get('passive_dns',[]))} DNS records")
        except Exception as e:
            self._warn(f"AlienVault failed: {e}")

    # ── URLScan.io ───────────────────────────────────────────────────
    def _run_urlscan(self):
        self._info("URLScan.io → historical scan data")
        try:
            query = urllib.parse.quote(f"domain:{self.target}")
            url   = f"https://urlscan.io/api/v1/search/?q={query}&size=100"
            req   = urllib.request.Request(
                url, headers={"User-Agent": "M7Hunter/5.0"})
            resp  = urllib.request.urlopen(req, timeout=20)
            data  = json.loads(resp.read().decode())
            for result in data.get("results", []):
                task = result.get("task", {})
                page = result.get("page", {})
                scan_url  = task.get("url","")
                domain    = page.get("domain","")
                ip_addr   = page.get("ip","")
                if scan_url:
                    self.results["urls_found"].append(scan_url)
                if domain and (domain.endswith(f".{self.target}") or domain == self.target):
                    self.results["subdomains"].add(domain)
                if ip_addr and re.match(r'^\d+\.\d+\.\d+\.\d+$', ip_addr):
                    self.results["ips"].add(ip_addr)
            self._success(f"URLScan: {len(data.get('results',[]))} results")
        except Exception as e:
            self._warn(f"URLScan failed: {e}")

    # ── Shodan ───────────────────────────────────────────────────────
    def _run_shodan(self):
        self._info("Shodan → exposed services + ports")
        api_key = self._get_key("shodan_key")
        queries = [
            f"hostname:{self.target}",
            f"hostname:*.{self.target}",
            f"ssl.cert.subject.cn:{self.target}",
        ]
        for query in queries:
            try:
                q   = urllib.parse.quote(query)
                url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={q}&limit=50"
                req = urllib.request.Request(url, headers={"User-Agent": "M7Hunter/5.0"})
                resp= urllib.request.urlopen(req, timeout=20)
                data= json.loads(resp.read().decode())
                for match in data.get("matches", []):
                    ip   = match.get("ip_str","")
                    port = match.get("port",0)
                    host = match.get("hostnames",[""])[0]
                    org  = match.get("org","")
                    banner = str(match.get("data",""))[:200]
                    if ip:
                        self.results["ips"].add(ip)
                    if host and host.endswith(f".{self.target}"):
                        self.results["subdomains"].add(host)
                    if port:
                        self.results["exposed_ports"].append({
                            "ip": ip, "port": port,
                            "org": org, "banner": banner[:100],
                            "hostname": host,
                        })
                time.sleep(1)  # Shodan rate limit
            except Exception as e:
                self._warn(f"Shodan query '{query[:30]}' failed: {e}")

        self._success(f"Shodan: {len(self.results['exposed_ports'])} services found")

    # ── Censys ───────────────────────────────────────────────────────
    def _run_censys(self):
        self._info("Censys → TLS intel + hidden subdomains")
        api_id     = self._get_key("censys_id")
        api_secret = self._get_key("censys_secret")

        try:
            import base64
            creds  = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
            query  = f"parsed.names: {self.target}"
            payload= json.dumps({"query": query, "page": 1, "fields": ["ip", "parsed.names", "ports.port"]}).encode()
            req    = urllib.request.Request(
                "https://search.censys.io/api/v2/hosts/search",
                data=payload,
                headers={
                    "Authorization": f"Basic {creds}",
                    "Content-Type" : "application/json",
                    "User-Agent"   : "M7Hunter/5.0",
                }
            )
            resp = urllib.request.urlopen(req, timeout=20)
            data = json.loads(resp.read().decode())
            for hit in data.get("result", {}).get("hits", []):
                ip    = hit.get("ip","")
                names = hit.get("parsed.names",[])
                if ip: self.results["ips"].add(ip)
                for name in names:
                    if name.endswith(f".{self.target}") or name == self.target:
                        self.results["subdomains"].add(name)
            self._success(f"Censys: results processed")
        except Exception as e:
            self._warn(f"Censys failed: {e}")

    # ── VirusTotal ───────────────────────────────────────────────────
    def _run_virustotal(self):
        self._info("VirusTotal → passive DNS + subdomains")
        api_key = self._get_key("vt_key")
        try:
            url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={self.target}"
            req = urllib.request.Request(url, headers={"User-Agent": "M7Hunter/5.0"})
            resp= urllib.request.urlopen(req, timeout=20)
            data= json.loads(resp.read().decode())
            subs = data.get("subdomains", [])
            for sub in subs:
                self.results["subdomains"].add(sub)
            self._success(f"VirusTotal: {len(subs)} subdomains")
        except Exception as e:
            self._warn(f"VirusTotal failed: {e}")

    # ── GitHub OSINT ─────────────────────────────────────────────────
    def _run_github_osint(self):
        self._info("GitHub → leaked secrets, exposed files")
        token = self._get_key("github_token")
        dorks = [
            f'"{self.target}" filename:.env',
            f'"{self.target}" filename:config.php',
            f'"{self.target}" password',
            f'"{self.target}" secret',
            f'"{self.target}" api_key',
            f'"{self.target}" aws_access_key_id',
            f'"{self.target}" database_url',
            f'site:{self.target} ext:env',
        ]
        found = 0
        for dork in dorks:
            try:
                q   = urllib.parse.quote(dork)
                url = f"https://api.github.com/search/code?q={q}&per_page=5"
                headers = {
                    "Accept"    : "application/vnd.github.v3+json",
                    "User-Agent": "M7Hunter/5.0",
                }
                if token:
                    headers["Authorization"] = f"token {token}"
                req  = urllib.request.Request(url, headers=headers)
                resp = urllib.request.urlopen(req, timeout=15)
                data = json.loads(resp.read().decode())
                for item in data.get("items", []):
                    self.results["leaked_files"].append({
                        "dork"      : dork[:60],
                        "file"      : item.get("name",""),
                        "url"       : item.get("html_url",""),
                        "repo"      : item.get("repository",{}).get("full_name",""),
                    })
                    found += 1
                time.sleep(3 if token else 8)
            except Exception as e:
                self._warn(f"GitHub dork failed: {e}")
                time.sleep(5)

        self._success(f"GitHub: {found} potential leaked files")

    # ── Save ─────────────────────────────────────────────────────────
    def _save(self):
        # Convert sets to lists for JSON
        save_data = dict(self.results)
        save_data["subdomains"] = sorted(list(self.results["subdomains"]))
        save_data["ips"]        = sorted(list(self.results["ips"]))
        save_data["target"]     = self.target

        out_file = os.path.join(self.out, f"osint_{self.target[:20]}.json")
        with open(out_file, "w") as f:
            json.dump(save_data, f, indent=2)

        # Write subdomains to pipeline's subdomains file
        if self.pipeline:
            subs_file = self.pipeline.files.get("subdomains", "")
            if subs_file:
                with open(subs_file, "a") as f:
                    for sub in save_data["subdomains"]:
                        f.write(sub + "\n")

        self._success(f"OSINT saved → {out_file}")

    def _print_summary(self):
        print(f"\n{B}━━━ OSINT Summary ━━━{RST}")
        print(f"  {C}Subdomains found : {W}{len(self.results['subdomains'])}{RST}")
        print(f"  {C}IPs discovered   : {W}{len(self.results['ips'])}{RST}")
        print(f"  {C}Exposed services : {W}{len(self.results['exposed_ports'])}{RST}")
        print(f"  {C}Leaked files     : {W}{len(self.results['leaked_files'])}{RST}")
        print(f"  {C}URLs found       : {W}{len(self.results['urls_found'])}{RST}")
        print()
        if self.results["leaked_files"]:
            print(f"  {R}[CRITICAL] Potential leaked files on GitHub:{RST}")
            for lf in self.results["leaked_files"][:5]:
                print(f"    → {lf['url'][:80]}")

    # ── Helpers ──────────────────────────────────────────────────────
    def _get_key(self, name: str) -> str:
        if self.cfg:
            return self.cfg.get(name, "") or ""
        return ""

    def _info(self, msg):
        if self.log: self.log.info(msg)
        else: print(f"  {C}[*]{RST} {msg}")

    def _success(self, msg):
        if self.log: self.log.success(msg)
        else: print(f"  {G}[✓]{RST} {msg}")

    def _warn(self, msg):
        if self.log: self.log.warn(msg)
        else: print(f"  {Y}[!]{RST} {msg}")
