#!/usr/bin/env python3
# core/installer.py

import os, shutil, subprocess

EXTRA = [
    "/usr/bin","/usr/local/bin","/usr/local/go/bin",
    os.path.expanduser("~/go/bin"),
    os.path.expanduser("~/.local/bin"),
    "/snap/bin",
]

TOOLS = {
    # name: (binary, method, install_cmd)
    "subfinder"  :("subfinder",  "go",  "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    "httpx"      :("httpx",      "go",  "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    "nuclei"     :("nuclei",     "go",  "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    "naabu"      :("naabu",      "go",  "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    "dnsx"       :("dnsx",       "go",  "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    "katana"     :("katana",     "go",  "go install github.com/projectdiscovery/katana/cmd/katana@latest"),
    "dalfox"     :("dalfox",     "go",  "go install github.com/hahwul/dalfox/v2@latest"),
    "hakrawler"  :("hakrawler",  "go",  "go install github.com/hakluke/hakrawler@latest"),
    "waybackurls":("waybackurls","go",  "go install github.com/tomnomnom/waybackurls@latest"),
    "gau"        :("gau",        "go",  "go install github.com/lc/gau/v2/cmd/gau@latest"),
    "subzy"      :("subzy",      "go",  "go install github.com/PentestPanic/subzy@latest"),
    "gf"         :("gf",         "go",  "go install github.com/tomnomnom/gf@latest"),
    "anew"       :("anew",       "go",  "go install github.com/tomnomnom/anew@latest"),
    "gowitness"  :("gowitness",  "go",  "go install github.com/sensepost/gowitness@latest"),
    "ffuf"       :("ffuf",       "go",  "go install github.com/ffuf/ffuf/v2@latest"),
    "arjun"      :("arjun",      "pip", "pip3 install arjun --break-system-packages"),
    "nmap"       :("nmap",       "apt", "apt-get install -y nmap"),
    "masscan"    :("masscan",    "apt", "apt-get install -y masscan"),
    "sqlmap"     :("sqlmap",     "apt", "apt-get install -y sqlmap"),
    "amass"      :("amass",      "apt", "apt-get install -y amass"),
    "tor"        :("tor",        "apt", "apt-get install -y tor"),
    "proxychains4":("proxychains4","apt","apt-get install -y proxychains4"),
    "massdns"    :("massdns",    "apt", "apt-get install -y massdns"),
    "wpscan"     :("wpscan",     "gem", "gem install wpscan"),
    "curl"       :("curl",       "apt", "apt-get install -y curl"),
    "jq"         :("jq",         "apt", "apt-get install -y jq"),
    "git"        :("git",        "apt", "apt-get install -y git"),
}

G="\033[92m"; Y="\033[93m"; R="\033[91m"; C="\033[96m"; RST="\033[0m"

class ToolInstaller:
    def __init__(self, log): self.log = log

    def _found(self, cmd):
        if shutil.which(cmd): return True
        for d in EXTRA:
            if os.path.isfile(os.path.join(d, cmd)) and os.access(os.path.join(d, cmd), os.X_OK):
                return True
        return False

    def _run(self, cmd):
        r = subprocess.run(cmd, shell=True, capture_output=True)
        return r.returncode == 0

    def check_only(self):
        self.log.section("Pre-flight Tool Check")
        ok, miss = [], []
        for name, (binary, _, _) in TOOLS.items():
            (ok if self._found(binary) else miss).append(name)
        print(f"  {G}Installed ({len(ok)}):{RST} {', '.join(ok)}")
        if miss:
            print(f"  {Y}Missing  ({len(miss)}):{RST} {', '.join(miss)}")
            print(f"\n  {C}Run --install to auto-install all missing tools.{RST}\n")
        else:
            print(f"  {G}All tools ready!{RST}\n")

    def install_all(self):
        self.log.section("Installing All Tools")
        # Ensure Go
        if not self._found("go"):
            self.log.info("Installing Go...")
            self._run("apt-get update -qq && apt-get install -y golang-go")
        # Set GOPATH
        gobin = os.path.expanduser("~/go/bin")
        os.environ["GOPATH"] = os.path.expanduser("~/go")
        os.environ["PATH"]   = gobin + ":" + os.environ.get("PATH","")

        for name,(binary,method,cmd) in TOOLS.items():
            if self._found(binary):
                print(f"  {G}[✓]{RST} {name:20s} already installed")
                continue
            print(f"  {Y}[↓]{RST} {name:20s}", end=" ", flush=True)
            if self._run(cmd): print(f"{G}done{RST}")
            else:              print(f"{R}FAILED{RST}")

        self._gf_patterns()
        if self._found("nuclei"):
            self.log.info("Updating Nuclei templates...")
            self._run("nuclei -update-templates -silent")
        # SecLists
        if not os.path.isdir("/usr/share/seclists"):
            self.log.info("Installing SecLists...")
            self._run("apt-get install -y seclists -qq || "
                      "git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists")
        self.log.success("Installation complete!")

    def _gf_patterns(self):
        gf_dir = os.path.expanduser("~/.gf")
        if os.path.isdir(gf_dir) and os.listdir(gf_dir):
            self.log.info("gf patterns already present")
            return
        os.makedirs(gf_dir, exist_ok=True)
        self._run(f"git clone --quiet https://github.com/1ndianl33t/Gf-Patterns /tmp/gfp && cp /tmp/gfp/*.json {gf_dir}/")
        self._run(f"git clone --quiet https://github.com/tomnomnom/gf /tmp/gfs && cp /tmp/gfs/examples/*.json {gf_dir}/")
