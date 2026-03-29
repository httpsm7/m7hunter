#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#   M7HUNTER v5.0 — One-Click Installer
#   Dual-Phase · Confidence Engine · OSINT · Telegram Bot
#   Made by MilkyWay Intelligence | Author: Sharlix
# ═══════════════════════════════════════════════════════════════════
set -e

R='\033[91m'; B='\033[34m'; G='\033[92m'
Y='\033[93m'; C='\033[96m'; W='\033[97m'; RST='\033[0m'

print_banner(){
cat << 'EOF'

        /\
       /  \
      /    \
     /  👁  \
    /________\
  ══════════════════════════════════════════════

  M7HUNTER v5.0 — World's #1 Bug Bounty Pipeline
  Dual-Phase · Confidence Engine · Proof Generator
  Made by MilkyWay Intelligence | Author: Sharlix

══════════════════════════════════════════════
EOF
}

ok()   { echo -e "${G}[✓]${RST} $1"; }
info() { echo -e "${C}[*]${RST} $1"; }
warn() { echo -e "${Y}[!]${RST} $1"; }
err()  { echo -e "${R}[✗]${RST} $1"; }
sec()  { echo -e "\n${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}";
         echo -e "${B}  ▶  ${W}$1${RST}";
         echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}\n"; }

print_banner

[ "$EUID" -ne 0 ] && { err "Run as root: sudo bash install.sh"; exit 1; }

exists(){ command -v "$1" &>/dev/null && return 0
  for d in /usr/bin /usr/local/bin /usr/local/go/bin "$HOME/go/bin" "$HOME/.local/bin" /snap/bin; do
    [ -x "$d/$1" ] && return 0; done; return 1; }

# ── APT ──────────────────────────────────────────────────────────
sec "APT Tools"
apt-get update -qq 2>/dev/null
APT_PKGS="nmap masscan sqlmap tor proxychains4 massdns amass jq curl git
          python3 python3-pip dnsutils ruby ruby-dev build-essential
          libcurl4-openssl-dev make gcc"
for pkg in $APT_PKGS; do
  exists "$pkg" && ok "$pkg" || {
    info "Installing $pkg..."
    apt-get install -y "$pkg" -qq 2>/dev/null && ok "$pkg" || warn "$pkg failed"
  }
done

# ── Go ────────────────────────────────────────────────────────────
sec "Go Language"
if exists go; then
  ok "Go: $(go version 2>/dev/null | awk '{print $3}')"
else
  info "Installing Go..."
  apt-get install -y golang-go -qq 2>/dev/null || snap install go --classic 2>/dev/null
fi
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"
grep -q 'GOPATH' /root/.bashrc 2>/dev/null || {
  echo 'export GOPATH=$HOME/go' >> /root/.bashrc
  echo 'export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin' >> /root/.bashrc
}

# ── Go Tools ──────────────────────────────────────────────────────
sec "Go Security Tools"
declare -A GOTOOLS=(
  ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
  ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  ["naabu"]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
  ["dalfox"]="github.com/hahwul/dalfox/v2@latest"
  ["hakrawler"]="github.com/hakluke/hakrawler@latest"
  ["waybackurls"]="github.com/tomnomnom/waybackurls@latest"
  ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
  ["subzy"]="github.com/PentestPanic/subzy@latest"
  ["gf"]="github.com/tomnomnom/gf@latest"
  ["anew"]="github.com/tomnomnom/anew@latest"
  ["gowitness"]="github.com/sensepost/gowitness@latest"
  ["ffuf"]="github.com/ffuf/ffuf/v2@latest"
  ["kxss"]="github.com/Emoe/kxss@latest"
  ["trufflehog"]="github.com/trufflesecurity/trufflehog/v3@latest"
)
for tool in "${!GOTOOLS[@]}"; do
  exists "$tool" && ok "$tool" || {
    info "Installing $tool..."
    go install -v "${GOTOOLS[$tool]}" &>/dev/null \
      && ok "$tool" || warn "$tool failed"
  }
done

# ── Python Packages ───────────────────────────────────────────────
sec "Python Packages"
pip3 install --break-system-packages --quiet \
  requests stem colorama tqdm rich arjun cloud-enum 2>/dev/null || true
ok "Python packages done"

# ── WPScan ────────────────────────────────────────────────────────
sec "WPScan"
exists wpscan && ok "WPScan installed" || {
  gem install wpscan 2>/dev/null && ok "WPScan done" || warn "WPScan failed"
}

# ── SecLists ──────────────────────────────────────────────────────
sec "SecLists Wordlists"
[ -d "/usr/share/seclists" ] && ok "SecLists installed" || {
  apt-get install -y seclists -qq 2>/dev/null \
  || git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists 2>/dev/null
  ok "SecLists done"
}

# ── GF Patterns ───────────────────────────────────────────────────
sec "GF Patterns"
GF_DIR="$HOME/.gf"
mkdir -p "$GF_DIR"
ls "$GF_DIR"/*.json &>/dev/null || {
  git clone --quiet https://github.com/1ndianl33t/Gf-Patterns /tmp/gfp 2>/dev/null \
    && cp /tmp/gfp/*.json "$GF_DIR/" 2>/dev/null && ok "GF patterns added"
}

# ── Nuclei Templates ──────────────────────────────────────────────
sec "Nuclei Templates"
exists nuclei && {
  nuclei -update-templates -silent 2>/dev/null && ok "Templates updated"
} || warn "nuclei not found"

# ── M7Hunter Intelligence Dirs ────────────────────────────────────
sec "M7Hunter Data Directories"
mkdir -p "$HOME/.m7hunter/sessions"
mkdir -p "$HOME/.m7hunter/secure"
mkdir -p "$HOME/.m7hunter/audit"
chmod 700 "$HOME/.m7hunter/secure"
ok "Intelligence directories created"

# ── Tor ───────────────────────────────────────────────────────────
sec "Tor Configuration"
cat > /etc/tor/torrc << 'TORRC'
SocksPort 9050
ControlPort 9051
HashedControlPassword 16:E600ADC90A2E3F9D8F0A4D24BCFF62C8F6C1E9B3D2A1F0E9C8B7A6D5
DataDirectory /var/lib/tor
TORRC
systemctl enable tor 2>/dev/null
systemctl restart tor 2>/dev/null || service tor start 2>/dev/null
ok "Tor configured"

# ── ProxyChains ───────────────────────────────────────────────────
for f in /etc/proxychains4.conf /etc/proxychains.conf; do
  [ -f "$f" ] && {
    grep -q "127.0.0.1 9050" "$f" || echo "socks5 127.0.0.1 9050" >> "$f"
    sed -i 's/^#quiet_mode/quiet_mode/' "$f" 2>/dev/null
    ok "ProxyChains configured"; break
  }
done

# ── Global Command ────────────────────────────────────────────────
sec "M7Hunter v5.0 Global Command"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cat > /usr/local/bin/m7hunter << WRAP
#!/usr/bin/env bash
exec python3 "${SCRIPT_DIR}/m7hunter.py" "\$@"
WRAP
chmod +x /usr/local/bin/m7hunter
mkdir -p "${SCRIPT_DIR}/results"
ok "Global command installed: m7hunter"

# ── Summary ───────────────────────────────────────────────────────
echo ""
echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo -e "${G}  ✅  M7Hunter v5.0 — Installation Complete!${RST}"
echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo ""
echo -e "  ${C}Quick Start:${RST}"
echo -e "  ${W}sudo m7hunter -u example.com --fast${RST}"
echo -e "  ${W}sudo m7hunter -u example.com --deep${RST}"
echo -e "  ${W}sudo m7hunter -u example.com --deep --osint --proof${RST}"
echo -e "  ${W}sudo m7hunter --dashboard${RST}"
echo -e "  ${W}sudo m7hunter --telegram-bot --telegram-token TOKEN${RST}"
echo -e "  ${W}sudo m7hunter --open-your-brain${RST}"
echo ""
echo -e "  ${C}Optional AI setup (local LLM):${RST}"
echo -e "  ${W}sudo m7hunter --setup-ai${RST}"
echo ""
