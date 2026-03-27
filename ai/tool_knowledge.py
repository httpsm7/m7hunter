#!/usr/bin/env python3
# ai/tool_knowledge.py — Complete Tool Command Database + Auto-Fix Engine
# Har tool ki sahi command pehle se stored hai
# Galat command detect karta hai aur khud fix karta hai
# MilkyWay Intelligence | Author: Sharlix

import os
import re
import subprocess
import shutil

# ═══════════════════════════════════════════════════════════════════
#  MASTER TOOL KNOWLEDGE BASE
#  Har tool ke liye:
#    - correct commands (version-aware)
#    - common broken variants
#    - auto-fix rules
#    - expected output format
#    - timeout recommendation
# ═══════════════════════════════════════════════════════════════════

TOOL_KB = {

    # ── Subdomain tools ───────────────────────────────────────────

    "subfinder": {
        "binary"    : "subfinder",
        "install"   : "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "version_cmd": "subfinder -version",
        "commands"  : {
            "passive"     : "subfinder -d {domain} -silent -all",
            "with_output" : "subfinder -d {domain} -silent -all -o {output}",
            "brute"       : "subfinder -d {domain} -w {wordlist} -silent",
        },
        "broken_patterns": [
            (r"-dL\s", "subfinder uses -dL for file input, -d for single domain"),
            (r"subfinder\s+{domain}", "missing -d flag"),
        ],
        "output_format" : "plain domain per line",
        "timeout_sec"   : 120,
        "docs_url"      : "https://github.com/projectdiscovery/subfinder",
    },

    "amass": {
        "binary"    : "amass",
        "install"   : "apt-get install -y amass",
        "version_cmd": "amass -version",
        "commands"  : {
            "passive"     : "amass enum -passive -d {domain} -timeout 5",
            "active"      : "amass enum -active -d {domain} -timeout 10",
            "with_output" : "amass enum -passive -d {domain} -o {output} -timeout 5",
        },
        "broken_patterns": [
            (r"amass\s+-d", "amass requires 'enum' subcommand: amass enum -d"),
            (r"amass enum -d\s+\S+ 2>/dev/null$", "amass needs -timeout flag to prevent hanging"),
        ],
        "auto_fix"  : {
            "amass -d {domain}": "amass enum -passive -d {domain} -timeout 5",
            "amass enum -d {domain}": "amass enum -passive -d {domain} -timeout 5",
        },
        "output_format" : "plain domain per line",
        "timeout_sec"   : 300,
        "docs_url"      : "https://github.com/owasp-amass/amass",
    },

    "dnsx": {
        "binary"    : "dnsx",
        "install"   : "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "version_cmd": "dnsx -version",
        "commands"  : {
            "resolve"     : "dnsx -l {input} -silent -a -resp-only",
            "with_cname"  : "dnsx -l {input} -silent -a -cname -resp",
            "brute"       : "dnsx -d {domain} -w {wordlist} -silent -resp-only",
        },
        "broken_patterns": [
            (r"dnsx -l .* -resp(?!\s*-only|-\w)", "dnsx -resp alone prints extra format — use -resp-only for clean output"),
        ],
        "output_format" : "hostname [IP] — strip [IP] for bare domains",
        "post_process"  : "sed 's/ \\[.*//g'",
        "timeout_sec"   : 120,
        "docs_url"      : "https://github.com/projectdiscovery/dnsx",
    },

    # ── HTTP tools ────────────────────────────────────────────────

    "httpx": {
        "binary"    : "httpx",
        "install"   : "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "version_cmd": "httpx -version",
        "commands"  : {
            "probe_clean" : "httpx -l {input} -silent -threads {threads} -follow-redirects -mc 200,201,301,302,403 -o {output}",
            "probe_verbose": "httpx -l {input} -silent -threads {threads} -status-code -title -tech-detect -o {output}",
            "probe_basic" : "httpx -l {input} -silent -threads {threads} -o {output}",
        },
        "broken_patterns": [
            (r"httpx.*-status-code.*-title.*-o\s", "httpx with -status-code -title produces 'URL [200] [Title]' format — breaks downstream tools. Use probe_clean mode for output files."),
        ],
        "auto_fix"  : {
            # If -status-code -title used with -o, strip those flags
            "remove_from_output_cmd": ["-status-code", "-title", "-tech-detect", "-tls-grab"],
        },
        "output_format" : "https://domain.com (one URL per line, no suffixes)",
        "timeout_sec"   : 120,
        "docs_url"      : "https://github.com/projectdiscovery/httpx",
    },

    # ── Port scanning ─────────────────────────────────────────────

    "nmap": {
        "binary"    : "nmap",
        "install"   : "apt-get install -y nmap",
        "version_cmd": "nmap --version",
        "commands"  : {
            "service_scan": "nmap -iL {input} -sV -T4 --open --script=http-title,banner -oN {output}",
            "quick"       : "nmap -iL {input} -F -T4 --open -oN {output}",
            "single_host" : "nmap {host} -sV -T4 --open -oN {output}",
        },
        "broken_patterns": [
            (r"nmap -iL .*(https?://)", "nmap -iL needs bare IP/hostname — no https:// prefix. Strip with: sed 's|https\\?://||g'"),
            (r"nmap\s+https?://", "nmap cannot handle URL format — strip scheme first"),
        ],
        "pre_process"   : "sed 's|https\\?://||g; s|/.*||; s|:.*||'",
        "input_format"  : "bare hostname or IP — NO https:// NO port NO path",
        "output_format" : "nmap XML/normal report",
        "timeout_sec"   : 600,
        "docs_url"      : "https://nmap.org/book/man.html",
    },

    "naabu": {
        "binary"    : "naabu",
        "install"   : "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "version_cmd": "naabu -version",
        "commands"  : {
            "top1000" : "naabu -l {input} -top-ports 1000 -silent -rate {rate} -o {output}",
            "full"    : "naabu -l {input} -p - -silent -rate {rate} -o {output}",
            "fast"    : "naabu -l {input} -top-ports 100 -silent -o {output}",
        },
        "input_format"  : "bare hostname or IP",
        "timeout_sec"   : 300,
        "docs_url"      : "https://github.com/projectdiscovery/naabu",
    },

    # ── Crawlers ──────────────────────────────────────────────────

    "katana": {
        "binary"    : "katana",
        "install"   : "go install github.com/projectdiscovery/katana/cmd/katana@latest",
        "version_cmd": "katana -version",
        "commands"  : {
            "deep"    : "katana -list {input} -d 3 -silent -jc -c {threads}",
            "passive" : "katana -list {input} -d 2 -silent",
            "js"      : "katana -list {input} -d 3 -silent -jc -ef css,png,jpg,gif",
        },
        "input_format"  : "https://domain.com (full URL required)",
        "timeout_sec"   : 300,
        "docs_url"      : "https://github.com/projectdiscovery/katana",
    },

    "hakrawler": {
        "binary"    : "hakrawler",
        "install"   : "go install github.com/hakluke/hakrawler@latest",
        "version_cmd": "hakrawler -h",
        "commands"  : {
            "default" : "cat {input} | hakrawler -d 2 -t {threads}",
            "deep"    : "cat {input} | hakrawler -d 3 -t {threads} -u",
        },
        "input_format"  : "stdin — pipe URLs in",
        "timeout_sec"   : 180,
    },

    "gau": {
        "binary"    : "gau",
        "install"   : "go install github.com/lc/gau/v2/cmd/gau@latest",
        "version_cmd": "gau --version",
        "commands"  : {
            "default"     : "gau --blacklist png,jpg,gif,svg,css,woff --timeout 30 {domain}",
            "with_subs"   : "gau --subs --blacklist png,jpg,gif --timeout 30 {domain}",
            "with_timeout": "timeout 120 gau --timeout 30 {domain}",
        },
        "broken_patterns": [
            (r"gau\s+\S+\s*$(?!.*--timeout)", "gau without --timeout will hang indefinitely on slow targets"),
            (r"gau\s+https?://", "gau needs bare domain, not URL: use domain.com not https://domain.com"),
        ],
        "auto_fix"  : {
            "add_timeout_if_missing": "--timeout 30",
            "strip_url_scheme"      : True,
        },
        "input_format"  : "bare domain — no https://",
        "timeout_sec"   : 130,
    },

    "waybackurls": {
        "binary"    : "waybackurls",
        "install"   : "go install github.com/tomnomnom/waybackurls@latest",
        "version_cmd": "waybackurls -h",
        "commands"  : {
            "default" : "echo {domain} | waybackurls",
            "dates"   : "echo {domain} | waybackurls --dates",
        },
        "input_format"  : "bare domain via stdin",
        "timeout_sec"   : 120,
    },

    # ── Vuln scanning ─────────────────────────────────────────────

    "nuclei": {
        "binary"    : "nuclei",
        "install"   : "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "version_cmd": "nuclei -version",
        "commands"  : {
            "default"     : "nuclei -l {input} -silent -severity critical,high,medium -o {output} -stats -no-color",
            "all_sev"     : "nuclei -l {input} -silent -severity critical,high,medium,low -o {output} -no-color",
            "custom_tpl"  : "nuclei -l {input} -t {template_dir} -silent -o {output} -no-color",
            "fast"        : "nuclei -l {input} -silent -severity critical,high -rl 50 -c 20 -o {output} -no-color",
            "with_proxy"  : "nuclei -l {input} -silent -proxy {proxy} -severity critical,high,medium -o {output} -no-color",
        },
        "input_format"  : "https://domain.com (full URL)",
        "output_format" : "[severity] template-id URL",
        "timeout_sec"   : 1800,
        "docs_url"      : "https://docs.projectdiscovery.io/tools/nuclei",
    },

    "dalfox": {
        "binary"    : "dalfox",
        "install"   : "go install github.com/hahwul/dalfox/v2@latest",
        "version_cmd": "dalfox version",
        "commands"  : {
            "file"    : "dalfox file {input} --skip-bav --silence --no-color -o {output}",
            "url"     : "dalfox url '{url}' --skip-bav --silence --no-color",
            "pipe"    : "cat {input} | dalfox pipe --skip-bav --silence --no-color",
            "with_cookie": "dalfox file {input} --cookie '{cookie}' --skip-bav --silence --no-color -o {output}",
        },
        "input_format"  : "file with URLs (one per line) OR single URL",
        "timeout_sec"   : 300,
        "docs_url"      : "https://github.com/hahwul/dalfox",
    },

    "sqlmap": {
        "binary"    : "sqlmap",
        "install"   : "apt-get install -y sqlmap",
        "version_cmd": "sqlmap --version",
        "commands"  : {
            "multi_target": "sqlmap -m {input} --batch --random-agent --level=2 --risk=2 --output-dir={outdir} --forms --crawl=2 --no-logging",
            "single_url"  : "sqlmap -u '{url}' --batch --random-agent --level=2 --risk=2 --output-dir={outdir} --no-logging",
            "with_cookie" : "sqlmap -m {input} --batch --random-agent --cookie='{cookie}' --level=2 --risk=2 --output-dir={outdir} --no-logging",
        },
        "output_format" : "directory with log files — parse for 'is vulnerable' string",
        "timeout_sec"   : 600,
        "docs_url"      : "https://github.com/sqlmapproject/sqlmap/wiki",
    },

    "ffuf": {
        "binary"    : "ffuf",
        "install"   : "go install github.com/ffuf/ffuf/v2@latest",
        "version_cmd": "ffuf -V",
        "commands"  : {
            "lfi"     : "ffuf -u '{url}' -w {wordlist}:FUZZ -mc 200 -fs 0 -silent",
            "dir"     : "ffuf -u '{url}/FUZZ' -w {wordlist} -mc 200,301,302,403 -silent",
            "vhost"   : "ffuf -u '{url}' -H 'Host: FUZZ.{domain}' -w {wordlist} -mc 200 -silent",
            "param"   : "ffuf -u '{url}?FUZZ=test' -w {wordlist} -mc 200 -silent",
        },
        "input_format"  : "URL with FUZZ placeholder",
        "timeout_sec"   : 300,
    },

    "subzy": {
        "binary"    : "subzy",
        "install"   : "go install github.com/PentestPanic/subzy@latest",
        "version_cmd": "subzy version",
        "commands"  : {
            "run"     : "subzy run --targets {input} --hide-fails --vuln",
            "single"  : "subzy run --target {domain} --hide-fails",
        },
        "broken_patterns": [
            (r"subzy.*--output\s", "subzy has no --output flag — pipe stdout instead: subzy run ... | tee output.txt"),
        ],
        "auto_fix"  : {
            "remove_flags": ["--output"],
            "use_pipe"    : True,
        },
        "input_format"  : "file with bare domains",
        "timeout_sec"   : 120,
        "docs_url"      : "https://github.com/PentestPanic/subzy",
    },

    "gf": {
        "binary"    : "gf",
        "install"   : "go install github.com/tomnomnom/gf@latest",
        "version_cmd": "gf -h",
        "commands"  : {
            "xss"     : "cat {input} | gf xss",
            "sqli"    : "cat {input} | gf sqli",
            "ssrf"    : "cat {input} | gf ssrf",
            "redirect": "cat {input} | gf redirect",
            "lfi"     : "cat {input} | gf lfi",
            "rce"     : "cat {input} | gf rce",
            "idor"    : "cat {input} | gf idor",
            "debug"   : "cat {input} | gf debug-pages",
        },
        "broken_patterns": [
            (r"gf\s+\w+\s+\S+\.txt", "gf reads from stdin not file arg: cat file.txt | gf pattern"),
        ],
        "notes"     : "Requires ~/.gf/*.json patterns. Install: git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf/",
        "timeout_sec"   : 30,
    },

    "gowitness": {
        "binary"    : "gowitness",
        "install"   : "go install github.com/sensepost/gowitness@latest",
        "version_cmd": "gowitness version",
        "commands"  : {
            "file"    : "gowitness scan file -f {input} --screenshot-path {outdir} --disable-logging",
            "single"  : "gowitness single {url} --screenshot-path {outdir}",
        },
        "input_format"  : "file with full URLs",
        "timeout_sec"   : 300,
    },

    "arjun": {
        "binary"    : "arjun",
        "install"   : "pip3 install arjun --break-system-packages",
        "version_cmd": "arjun --help",
        "commands"  : {
            "file"    : "arjun -i {input} -oT {output} -t {threads} -q",
            "single"  : "arjun -u '{url}' -oT {output} -q",
        },
        "input_format"  : "file with URLs OR single URL",
        "timeout_sec"   : 240,
    },

    "wpscan": {
        "binary"    : "wpscan",
        "install"   : "gem install wpscan",
        "version_cmd": "wpscan --version",
        "commands"  : {
            "default"    : "wpscan --url '{url}' --enumerate vp,vt,u --random-user-agent --output {output}",
            "with_token" : "wpscan --url '{url}' --enumerate vp,vt,u,ap --random-user-agent --api-token {token} --output {output}",
            "aggressive" : "wpscan --url '{url}' --enumerate vp,vt,u --detection-mode aggressive --output {output}",
        },
        "input_format"  : "single WordPress URL",
        "timeout_sec"   : 300,
    },

    "trufflehog": {
        "binary"    : "trufflehog",
        "install"   : "go install github.com/trufflesecurity/trufflehog/v3@latest",
        "version_cmd": "trufflehog --version",
        "commands"  : {
            "git"     : "trufflehog git {url} --no-update",
            "filesystem": "trufflehog filesystem {path} --no-update",
        },
        "timeout_sec"   : 120,
    },

    "kxss": {
        "binary"    : "kxss",
        "install"   : "go install github.com/Emoe/kxss@latest",
        "version_cmd": "kxss -h",
        "commands"  : {
            "default" : "cat {input} | kxss",
        },
        "input_format"  : "stdin — pipe URLs",
        "timeout_sec"   : 120,
    },
}


class ToolCommandEngine:
    """
    Tool ka command expert.
    - Kisi bhi tool ki correct command deta hai
    - Galat command detect karta hai
    - Auto-fix karta hai
    - Tool installed hai ya nahi check karta hai
    """

    def __init__(self, log=None):
        self.log = log
        self._tool_versions = {}

    def get_command(self, tool: str, mode: str = "default", **kwargs) -> str:
        """
        Correct command return karo.
        kwargs: domain, input, output, threads, rate, cookie, etc.
        """
        if tool not in TOOL_KB:
            return ""
        kb  = TOOL_KB[tool]
        cmds= kb.get("commands", {})

        # Find best matching command mode
        cmd_template = cmds.get(mode) or cmds.get("default") or list(cmds.values())[0]

        # Fill in placeholders
        for k, v in kwargs.items():
            cmd_template = cmd_template.replace(f"{{{k}}}", str(v))

        return cmd_template

    def validate_command(self, tool: str, command: str) -> tuple:
        """
        Check if command has known issues.
        Returns: (is_valid, issue_description, fixed_command)
        """
        if tool not in TOOL_KB:
            return True, "", command

        kb = TOOL_KB[tool]
        broken = kb.get("broken_patterns", [])

        for pattern, issue in broken:
            if re.search(pattern, command):
                fixed = self._auto_fix(tool, command, kb)
                return False, issue, fixed

        return True, "", command

    def _auto_fix(self, tool: str, command: str, kb: dict) -> str:
        """Apply auto-fix rules to broken command."""
        auto_fix = kb.get("auto_fix", {})

        # Remove problematic flags
        for flag in auto_fix.get("remove_flags", []):
            command = re.sub(rf'\s+{re.escape(flag)}\s+\S+', ' ', command)
            command = re.sub(rf'\s+{re.escape(flag)}', '', command)

        # Strip URL scheme if needed
        if auto_fix.get("strip_url_scheme"):
            command = re.sub(r'https?://', '', command)

        # Add missing flags
        if auto_fix.get("add_timeout_if_missing") and "--timeout" not in command:
            command = command.rstrip() + f" {auto_fix['add_timeout_if_missing']}"

        # Use pipe instead of --output flag
        if auto_fix.get("use_pipe") and "--output" in command:
            output_match = re.search(r'--output\s+(\S+)', command)
            if output_match:
                outfile = output_match.group(1)
                command = re.sub(r'\s+--output\s+\S+', '', command)
                command = f"({command}) | tee {outfile}"

        return command.strip()

    def check_tool(self, tool: str) -> dict:
        """Full tool health check."""
        if tool not in TOOL_KB:
            return {"installed": False, "error": "unknown tool"}

        kb     = TOOL_KB[tool]
        binary = kb["binary"]
        result = {
            "tool"     : tool,
            "binary"   : binary,
            "installed": False,
            "version"  : None,
            "path"     : None,
            "error"    : None,
        }

        # Check if binary exists
        path = shutil.which(binary)
        if path:
            result["installed"] = True
            result["path"]      = path
        else:
            # Check extra paths
            for d in [os.path.expanduser("~/go/bin"), "/usr/local/bin", "/usr/bin"]:
                fp = os.path.join(d, binary)
                if os.path.isfile(fp):
                    result["installed"] = True
                    result["path"]      = fp
                    break

        if not result["installed"]:
            result["error"] = f"Not found. Install: {kb.get('install','unknown')}"
            return result

        # Get version
        ver_cmd = kb.get("version_cmd","")
        if ver_cmd:
            try:
                r = subprocess.run(
                    ver_cmd.split(), capture_output=True, text=True, timeout=5)
                out = (r.stdout + r.stderr).strip().split("\n")[0]
                result["version"] = out[:80]
            except Exception:
                result["version"] = "unknown"

        return result

    def get_input_format(self, tool: str) -> str:
        return TOOL_KB.get(tool, {}).get("input_format", "unknown")

    def get_timeout(self, tool: str) -> int:
        return TOOL_KB.get(tool, {}).get("timeout_sec", 300)

    def get_docs_url(self, tool: str) -> str:
        return TOOL_KB.get(tool, {}).get("docs_url", "")

    def list_all_tools(self) -> list:
        return list(TOOL_KB.keys())
