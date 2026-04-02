#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#   M7HUNTER v7.0 — One-Click Installer
#   NEW: httpx[http2], playwright, websockets, asyncio tools
#   ⚠️  AUTHORIZED USE ONLY
#   MilkyWay Intelligence | Author: Sharlix
# ═══════════════════════════════════════════════════════════════════
set -e

R='\033[91m'; B='\033[34m'; G='\033[92m'
Y='\033[93m'; C='\033[96m'; W='\033[97m'; RST='\033[0m'

ok()   { echo -e "${G}[✓]${RST} $1"; }
info() { echo -e "${C}[*]${RST} $1"; }
warn() { echo -e "${Y}[!]${RST} $1"; }
sec()  { echo -e "\n${B}━━━ ${W}$1${RST}\n"; }

[ "$EUID" -ne 0 ] && { echo -e "${R}[✗] Run as root: sudo bash install_v7.sh${RST}"; exit 1; }

exists(){ command -v "$1" &>/dev/null && return 0
  for d in /usr/bin /usr/local/bin "$HOME/go/bin" "$HOME/.local/bin"; do
    [ -x "$d/$1" ] && return 0; done; return 1; }

sec "APT Tools"
apt-get update -qq 2>/dev/null
for pkg in nmap masscan sqlmap tor proxychains4 massdns amass jq curl git \
           python3 python3-pip dnsutils ruby ruby-dev build-essential \
           golang-go cargo rustc chromium chromium-driver; do
  exists "$pkg" && ok "$pkg" || {
    apt-get install -y "$pkg" -qq 2>/dev/null && ok "$pkg" || warn "$pkg skipped"
  }
done

sec "Go Language Setup"
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"
grep -q 'GOPATH' /root/.bashrc 2>/dev/null || {
  echo 'export GOPATH=$HOME/go' >> /root/.bashrc
  echo 'export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin' >> /root/.bashrc
}

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
  ["qsreplace"]="github.com/tomnomnom/qsreplace@latest"
  ["gospider"]="github.com/jaeles-project/gospider@latest"
  ["notify"]="github.com/projectdiscovery/notify/cmd/notify@latest"
  ["interactsh-client"]="github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
)
for tool in "${!GOTOOLS[@]}"; do
  exists "$tool" && ok "$tool" || {
    info "Installing $tool..."
    go install -v "${GOTOOLS[$tool]}" &>/dev/null && ok "$tool" || warn "$tool failed"
  }
done

sec "Python V7 Dependencies (HTTP/2, Async, WebSockets)"
pip3 install --break-system-packages --quiet \
  "httpx[http2]" \
  playwright \
  aiofiles \
  websockets \
  aiohttp \
  requests \
  stem colorama tqdm rich \
  arjun \
  wafw00f \
  cloud-enum \
  2>/dev/null || true
ok "Python packages installed"

sec "Playwright Chromium (headless browser for SPA crawling)"
playwright install chromium --with-deps 2>/dev/null \
  && ok "Playwright Chromium ready" \
  || warn "Playwright install failed — SPA crawling will use static fallback"

sec "WPScan"
exists wpscan && ok "WPScan" || {
  gem install wpscan --quiet 2>/dev/null && ok "WPScan" || warn "WPScan failed"
}

sec "Smuggler (HTTP Request Smuggling)"
SMUGGLER="$HOME/tools/smuggler"
[ -d "$SMUGGLER" ] && ok "smuggler" || {
  mkdir -p "$HOME/tools"
  git clone --quiet https://github.com/defparam/smuggler "$SMUGGLER" 2>/dev/null \
    && ok "smuggler" || warn "smuggler failed"
}

sec "SecLists"
[ -d "/usr/share/seclists" ] && ok "SecLists" || {
  apt-get install -y seclists -qq 2>/dev/null || \
  git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists 2>/dev/null
  ok "SecLists"
}

sec "GF Patterns"
GF_DIR="$HOME/.gf"; mkdir -p "$GF_DIR"
ls "$GF_DIR"/*.json &>/dev/null && ok "GF patterns" || {
  git clone --quiet https://github.com/1ndianl33t/Gf-Patterns /tmp/gfp 2>/dev/null \
    && cp /tmp/gfp/*.json "$GF_DIR/" 2>/dev/null && ok "GF patterns"
}

sec "Nuclei Templates"
exists nuclei && { nuclei -update-templates -silent 2>/dev/null && ok "Nuclei templates updated"; }

sec "M7Hunter Directories"
mkdir -p "$HOME/.m7hunter/sessions" "$HOME/.m7hunter/secure" \
         "$HOME/.m7hunter/audit" "$HOME/tools"
chmod 700 "$HOME/.m7hunter/secure"
ok "Directories created"

sec "Tor"
cat > /etc/tor/torrc << 'TORRC'
SocksPort 9050
ControlPort 9051
HashedControlPassword 16:E600ADC90A2E3F9D8F0A4D24BCFF62C8F6C1E9B3D2A1F0E9C8B7A6D5
DataDirectory /var/lib/tor
TORRC
systemctl enable tor 2>/dev/null; systemctl restart tor 2>/dev/null || service tor start 2>/dev/null
ok "Tor configured"

sec "Global Command"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cat > /usr/local/bin/m7hunter << WRAP
#!/usr/bin/env bash
exec python3 "${SCRIPT_DIR}/m7hunter.py" "\$@"
WRAP
chmod +x /usr/local/bin/m7hunter
ok "m7hunter command installed"

sec "Brain Credentials Setup"
echo -e "${Y}[!] Set admin credentials (required for brain access):${RST}"
echo -e "${W}    export M7_ADMIN_USER='yourusername'${RST}"
echo -e "${W}    export M7_ADMIN_PASS='yourpassword'${RST}"
echo -e "${C}    Or run: sudo m7hunter --setup-brain${RST}"

echo ""
echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo -e "${G}  ✅  M7Hunter V7 Installation Complete!${RST}"
echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo ""
echo -e "  ${C}V7 Quick Start:${RST}"
echo -e "  ${W}sudo m7hunter -u target.com --deep${RST}"
echo -e "  ${W}sudo m7hunter -u target.com --deep --cookie 'session=x'${RST}"
echo -e "  ${W}sudo m7hunter -u target.com --deep --userA 'sA=x' --userB 'sB=y'${RST}"
echo ""
echo -e "  ${C}V7 New Features:${RST}"
echo -e "  ${W}--no-double-verify${RST}  Skip confirmation step (faster)"
echo -e "  ${W}--no-http2${RST}          Disable HTTP/2"
echo -e "  ${W}--ws${RST}                WebSocket testing"
echo -e "  ${W}--proto-pollution${RST}   Prototype pollution"
echo ""
