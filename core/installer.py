#!/usr/bin/env python3
# core/installer.py — M7Hunter v3.0 Smart Installer

import os, shutil, subprocess

EXTRA_PATHS = [
    "/usr/bin", "/usr/local/bin", "/usr/local/go/bin",
    os.path.expanduser("~/go/bin"),
    os.path.expanduser("~/.local/bin"),
    "/snap/bin",
]

TOOLS = {
    "subfinder"   : ("subfinder",   "go",  "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    "httpx"       : ("httpx",       "go",  "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    "nuclei"      : ("nuclei",      "go",  "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    "naabu"       : ("naabu",       "go",  "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    "dnsx"        : ("dnsx",        "go",  "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    "katana"      : ("katana",      "go",  "go install github.com/projectdiscovery/katana/cmd/katana@latest"),
    "dalfox"      : ("dalfox",      "go",  "go install github.com/hahwul/dalfox/v2@latest"),
    "hakrawler"   : ("hakrawler",   "go",  "go install github.com/hakluke/hakrawler@latest"),
    "waybackurls" : ("waybackurls", "go",  "go install github.com/tomnomnom/waybackurls@latest"),
    "gau"         : ("gau",         "go",  "go install github.com/lc/gau/v2/cmd/gau@latest"),
    "subzy"       : ("subzy",       "go",  "go install github.com/PentestPanic/subzy@latest"),
    "gf"          : ("gf",          "go",  "go install github.com/tomnomnom/gf@latest"),
    "anew"        : ("anew",        "go",  "go install github.com/tomnomnom/anew@latest"),
    "gowitness"   : ("gowitness",   "go",  "go install github.com/sensepost/gowitness@latest"),
    "ffuf"        : ("ffuf",        "go",  "go install github.com/ffuf/ffuf/v2@latest"),
    "kxss"        : ("kxss",        "go",  "go install github.com/Emoe/kxss@latest"),
    "trufflehog"  : ("trufflehog",  "go",  "go install github.com/trufflesecurity/trufflehog/v3@latest"),
    "arjun"       : ("arjun",       "pip", "pip3 install arjun --break-system-packages"),
    "cloud_enum"  : ("cloud_enum",  "pip", "pip3 install cloud-enum --break-system-packages"),
    "nmap"        : ("nmap",        "apt", "apt-get install -y nmap"),
    "masscan"     : ("masscan",     "apt", "apt-get install -y masscan"),
    "sqlmap"      : ("sqlmap",      "apt", "apt-get install -y sqlmap"),
    "amass"       : ("amass",       "apt", "apt-get install -y amass"),
    "tor"         : ("tor",         "apt", "apt-get install -y tor"),
    "proxychains4": ("proxychains4","apt", "apt-get install -y proxychains4"),
    "massdns"     : ("massdns",     "apt", "apt-get install -y massdns"),
    "wpscan"      : ("wpscan",      "gem", "gem install wpscan"),
    "curl"        : ("curl",        "apt", "apt-get install -y curl"),
    "jq"          : ("jq",          "apt", "apt-get install -y jq"),
    "git"         : ("git",         "apt", "apt-get install -y git"),
}

G="\033[92m"; Y="\033[93m"; R="\033[91m"; C="\033[96m"; W="\033[97m"; RST="\033[0m"

class ToolInstaller:
    def __init__(self, log):
        self.log = log

    def _found(self, cmd):
        if shutil.which(cmd): return True
        for d in EXTRA_PATHS:
            full = os.path.join(d, cmd)
            if os.path.isfile(full) and os.access(full, os.X_OK): return True
        return False

    def _run(self, cmd):
        try:
            r = subprocess.run(
                cmd + " >/dev/null 2>&1",
                shell=True, timeout=300
            )
            return r.returncode == 0
        except subprocess.TimeoutExpired:
            return False

    def check_only(self):
        self.log.section("Pre-flight Tool Check")
        ok, miss = [], []
        for name,(binary,_,_) in TOOLS.items():
            (ok if self._found(binary) else miss).append(name)
        print(f"  {G}Installed ({len(ok)}):{RST} {', '.join(ok)}")
        if miss:
            print(f"  {Y}Missing  ({len(miss)}):{RST} {', '.join(miss)}")
            print(f"\n  {C}Run: sudo m7hunter --install{RST}\n")
        else:
            print(f"  {G}All tools ready!{RST}\n")

    def install_all(self):
        self.log.section("M7Hunter v3.0 — Full Install")
        self._run("apt-get update -qq")
        if not self._found("go"):
            self.log.info("Installing Go...")
            self._run("apt-get install -y golang-go -qq")
        gobin = os.path.expanduser("~/go/bin")
        os.environ["GOPATH"] = os.path.expanduser("~/go")
        os.environ["PATH"]   = gobin + ":/usr/local/go/bin:" + os.environ.get("PATH","")
        for name,(binary,method,cmd) in TOOLS.items():
            if self._found(binary):
                print(f"  {G}[✓]{RST} {name:20s} already installed")
                continue
            print(f"  {Y}[↓]{RST} {name:20s}", end=" ", flush=True)
            ok = self._run(cmd)
            print(f"{G}done{RST}" if ok else f"{R}FAILED{RST}")
        self._install_gf_patterns()
        if self._found("nuclei"):
            self.log.info("Updating Nuclei templates...")
            self._run("nuclei -update-templates -silent")
        if not os.path.isdir("/usr/share/seclists"):
            self.log.info("Installing SecLists...")
            self._run("apt-get install -y seclists -qq || git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists")
        self._configure_tor()
        self._configure_proxychains()
        self._install_command()
        self.log.success("Done! Run: sudo m7hunter --check")

    def update_all(self):
        self.log.section("Updating Tools")
        gobin = os.path.expanduser("~/go/bin")
        os.environ["GOPATH"] = os.path.expanduser("~/go")
        os.environ["PATH"]   = gobin + ":/usr/local/go/bin:" + os.environ.get("PATH","")
        for name,(binary,method,cmd) in TOOLS.items():
            if method == "go":
                print(f"  {C}[↑]{RST} {name:20s}", end=" ", flush=True)
                ok = self._run(cmd)
                print(f"{G}done{RST}" if ok else f"{R}FAILED{RST}")
        if self._found("nuclei"):
            self._run("nuclei -update-templates -silent")
            self.log.success("Nuclei templates updated")
        self.log.success("Update complete!")

    def _install_gf_patterns(self):
        gf_dir = os.path.expanduser("~/.gf")
        os.makedirs(gf_dir, exist_ok=True)
        if os.listdir(gf_dir):
            self.log.info("GF patterns present"); return
        self._run(f"git clone --quiet https://github.com/1ndianl33t/Gf-Patterns /tmp/gfp && cp /tmp/gfp/*.json {gf_dir}/")
        self._run(f"git clone --quiet https://github.com/tomnomnom/gf /tmp/gfs && cp /tmp/gfs/examples/*.json {gf_dir}/")
        self.log.success("GF patterns installed")

    def _configure_tor(self):
        try:
            with open("/etc/tor/torrc","w") as f:
                f.write("SocksPort 9050\nControlPort 9051\nHashedControlPassword 16:E600ADC90A2E3F9D8F0A4D24BCFF62C8F6C1E9B3D2A1F0E9C8B7A6D5\nDataDirectory /var/lib/tor\n")
            self._run("systemctl enable tor 2>/dev/null; systemctl restart tor 2>/dev/null")
            self.log.success("Tor configured")
        except Exception: self.log.warn("Tor: configure manually if needed")

    def _configure_proxychains(self):
        for cfg in ["/etc/proxychains4.conf","/etc/proxychains.conf"]:
            if os.path.isfile(cfg):
                try:
                    content = open(cfg).read()
                    if "127.0.0.1 9050" not in content:
                        open(cfg,"a").write("\nsocks5 127.0.0.1 9050\n")
                    open(cfg,"w").write(content.replace("#quiet_mode","quiet_mode"))
                    self.log.success("ProxyChains configured")
                except Exception: pass
                break

    def _install_command(self):
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        try:
            with open("/usr/local/bin/m7hunter","w") as f:
                f.write(f'#!/usr/bin/env bash\nexec python3 "{script_dir}/m7hunter.py" "$@"\n')
            os.chmod("/usr/local/bin/m7hunter",0o755)
            self.log.success("Global command: m7hunter")
        except Exception as e: self.log.warn(f"Global cmd failed: {e}")
