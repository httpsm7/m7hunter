#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#   M7HUNTER — One-Click Installer
#   Installs: APT tools, Go tools, Python deps, Ollama AI,
#             Playwright, WPScan, SecLists, GF Patterns, Tor, Smuggler
#   ⚠️  AUTHORIZED USE ONLY — MilkyWay Intelligence | Author: Sharlix
# ═══════════════════════════════════════════════════════════════════
set -e

R='\033[91m'; B='\033[34m'; G='\033[92m'
Y='\033[93m'; C='\033[96m'; W='\033[97m'; RST='\033[0m'

ok()   { echo -e "${G}[✓]${RST} $1"; }
info() { echo -e "${C}[*]${RST} $1"; }
warn() { echo -e "${Y}[!]${RST} $1"; }
err()  { echo -e "${R}[✗]${RST} $1"; }
sec()  { echo -e "\n${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"; \
         echo -e "${B}  ${W}$1${RST}"; \
         echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}\n"; }

# ── Root check ───────────────────────────────────────────────────
[ "$EUID" -ne 0 ] && { err "Run as root: sudo bash install.sh"; exit 1; }

exists() {
  command -v "$1" &>/dev/null && return 0
  for d in /usr/bin /usr/local/bin "$HOME/go/bin" "$HOME/.local/bin" /snap/bin; do
    [ -x "$d/$1" ] && return 0
  done
  return 1
}

# ── Banner ───────────────────────────────────────────────────────
echo ""
echo -e "${B}  ███╗   ███╗███████╗██╗  ██╗██╗   ██╗███╗  ██╗████████╗███████╗██████╗${RST}"
echo -e "${B}  ╚══██╗██╔╝╚════██║██║  ██║██║   ██║████╗ ██║╚══██╔══╝██╔════╝██╔══██╗${RST}"
echo -e "${C}     ████╔╝     ██╔╝███████║██║   ██║██╔██╗██║   ██║   █████╗  ██████╔╝${RST}"
echo -e "${C}    ██╔═██╗    ██╔╝ ██╔══██║╚██╗ ██╔╝██║╚████║   ██║   ██╔══╝  ██╔══██╗${RST}"
echo -e "${W}   ██║  ██╗   ██║  ██║  ██║ ╚████╔╝ ██║ ╚███║   ██║   ███████╗██║  ██║${RST}"
echo -e "${W}   ╚═╝  ╚═╝   ╚═╝  ╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝${RST}"
echo ""
echo -e "${Y}  MilkyWay Intelligence | Author: Sharlix | github.com/httpsm7${RST}"
echo ""

# ── 1. APT System Packages ───────────────────────────────────────
sec "APT System Packages"
apt-get update -qq 2>/dev/null

APT_PKGS=(
  nmap masscan sqlmap tor proxychains4 amass massdns
  jq curl git wget dnsutils build-essential
  python3 python3-pip ruby ruby-dev
  golang-go cargo
  chromium chromium-driver
)

for pkg in "${APT_PKGS[@]}"; do
  if exists "$pkg"; then
    ok "$pkg"
  else
    printf "  ${Y}[↓]${RST} %-20s" "$pkg"
    apt-get install -y "$pkg" -qq 2>/dev/null \
      && echo -e "${G}done${RST}" \
      || echo -e "${Y}skipped${RST}"
  fi
done

# ── 2. Go Environment ────────────────────────────────────────────
sec "Go Language Setup"
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"

grep -q 'GOPATH' /root/.bashrc 2>/dev/null || {
  echo 'export GOPATH=$HOME/go'                      >> /root/.bashrc
  echo 'export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin' >> /root/.bashrc
  ok "GOPATH added to .bashrc"
}
ok "Go environment ready"

# ── 3. Go Security Tools ─────────────────────────────────────────
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
  if exists "$tool"; then
    ok "$tool"
  else
    printf "  ${Y}[↓]${RST} %-22s" "$tool"
    go install "${GOTOOLS[$tool]}" &>/dev/null \
      && echo -e "${G}done${RST}" \
      || echo -e "${R}FAILED${RST}"
  fi
done

# ── 4. Python Dependencies ───────────────────────────────────────
sec "Python Dependencies (HTTP/2, Async, WebSockets)"

pip3 install --break-system-packages --quiet \
  "httpx[http2]" \
  playwright \
  aiofiles \
  websockets \
  aiohttp \
  requests \
  stem \
  colorama \
  tqdm \
  rich \
  arjun \
  wafw00f \
  cloud-enum \
  2>/dev/null || true

ok "Python packages installed"

# ── 5. Playwright Chromium ───────────────────────────────────────
sec "Playwright Chromium (Headless Browser for SPA Crawling)"

playwright install chromium --with-deps 2>/dev/null \
  && ok "Playwright Chromium ready" \
  || warn "Playwright install failed — SPA crawling will use static fallback"

# ── 6. WPScan ────────────────────────────────────────────────────
sec "WPScan (WordPress Scanner)"

if exists wpscan; then
  ok "WPScan already installed"
else
  gem install wpscan --quiet 2>/dev/null \
    && ok "WPScan installed" \
    || warn "WPScan failed — install manually: gem install wpscan"
fi

# ── 7. Smuggler (HTTP Request Smuggling) ─────────────────────────
sec "Smuggler (HTTP Request Smuggling)"

SMUGGLER="$HOME/tools/smuggler"
if [ -d "$SMUGGLER" ]; then
  ok "Smuggler already installed"
else
  mkdir -p "$HOME/tools"
  git clone --quiet https://github.com/defparam/smuggler "$SMUGGLER" 2>/dev/null \
    && ok "Smuggler installed at $SMUGGLER" \
    || warn "Smuggler clone failed — install manually"
fi

# ── 8. SecLists ──────────────────────────────────────────────────
sec "SecLists (Wordlists)"

if [ -d "/usr/share/seclists" ]; then
  ok "SecLists already present"
else
  apt-get install -y seclists -qq 2>/dev/null \
    || git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists 2>/dev/null
  ok "SecLists installed"
fi

# ── 9. GF Patterns ───────────────────────────────────────────────
sec "GF Patterns (grep-friendly vuln patterns)"

GF_DIR="$HOME/.gf"
mkdir -p "$GF_DIR"

if ls "$GF_DIR"/*.json &>/dev/null; then
  ok "GF patterns already present"
else
  git clone --quiet https://github.com/1ndianl33t/Gf-Patterns /tmp/gfp 2>/dev/null \
    && cp /tmp/gfp/*.json "$GF_DIR/" 2>/dev/null \
    && ok "GF patterns installed" \
    || warn "GF patterns failed"
fi

# ── 10. Nuclei Templates ─────────────────────────────────────────
sec "Nuclei Templates (auto-update)"

if exists nuclei; then
  nuclei -update-templates -silent 2>/dev/null && ok "Nuclei templates updated"
else
  warn "Nuclei not installed — skipping template update"
fi

# ── 11. Ollama AI (Local LLM) ────────────────────────────────────
sec "Ollama AI (Local LLM Brain)"

if exists ollama; then
  ok "Ollama already installed"
else
  info "Installing Ollama..."
  curl -fsSL https://ollama.com/install.sh | sh 2>/dev/null \
    && ok "Ollama installed" \
    || warn "Ollama install failed — install manually: https://ollama.com"
fi

# Pull llama3 model if ollama is available
if exists ollama; then
  info "Pulling llama3 model (this may take a few minutes on first run)..."
  echo -e "  ${Y}Run manually if needed: ollama pull llama3${RST}"
fi

# ── 12. Tor Configuration ────────────────────────────────────────
sec "Tor (IP Rotation)"

cat > /etc/tor/torrc << 'TORRC'
SocksPort 9050
ControlPort 9051
HashedControlPassword 16:E600ADC90A2E3F9D8F0A4D24BCFF62C8F6C1E9B3D2A1F0E9C8B7A6D5
DataDirectory /var/lib/tor
TORRC

systemctl enable tor 2>/dev/null || true
systemctl restart tor 2>/dev/null \
  || service tor start 2>/dev/null \
  || warn "Could not start Tor — start manually: service tor start"
ok "Tor configured (SOCKS5: 127.0.0.1:9050)"

# ── 13. M7Hunter Directories ─────────────────────────────────────
sec "M7Hunter Data Directories"

mkdir -p "$HOME/.m7hunter/sessions"
mkdir -p "$HOME/.m7hunter/secure"
mkdir -p "$HOME/.m7hunter/audit"
mkdir -p "$HOME/tools"
chmod 700 "$HOME/.m7hunter/secure"
ok "Directories created: ~/.m7hunter/"

# ── 14. Global Command ───────────────────────────────────────────
sec "Global 'm7hunter' Command"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cat > /usr/local/bin/m7hunter << WRAP
#!/usr/bin/env bash
exec python3 "${SCRIPT_DIR}/m7hunter.py" "\$@"
WRAP
chmod +x /usr/local/bin/m7hunter
ok "Global command installed: m7hunter"

# ── 15. Final Summary ────────────────────────────────────────────
echo ""
echo -e "${B}══════════════════════════════════════════════════════${RST}"
echo -e "${G}  ✅  M7Hunter Installation Complete!${RST}"
echo -e "${B}══════════════════════════════════════════════════════${RST}"
echo ""
echo -e "  ${C}Step 1 — Set Brain Credentials (required):${RST}"
echo -e "  ${W}export M7_ADMIN_USER='yourusername'${RST}"
echo -e "  ${W}export M7_ADMIN_PASS='yourpassword'${RST}"
echo -e "  ${W}echo 'export M7_ADMIN_USER=\"yourusername\"' >> ~/.bashrc${RST}"
echo -e "  ${W}echo 'export M7_ADMIN_PASS=\"yourpassword\"' >> ~/.bashrc${RST}"
echo ""
echo -e "  ${C}Step 2 — Start Ollama AI (optional but recommended):${RST}"
echo -e "  ${W}ollama serve &${RST}"
echo -e "  ${W}ollama pull llama3${RST}"
echo ""
echo -e "  ${C}Step 3 — Verify Installation:${RST}"
echo -e "  ${W}m7hunter --check${RST}"
echo ""
echo -e "  ${C}Step 4 — Run First Scan:${RST}"
echo -e "  ${W}sudo m7hunter -u target.com --deep${RST}"
echo -e "  ${W}sudo m7hunter -u target.com --deep --cookie 'session=x'${RST}"
echo -e "  ${W}sudo m7hunter -u target.com --deep --userA 'sA=x' --userB 'sB=y'${RST}"
echo ""
echo -e "  ${C}Dashboard (open http://localhost:8719):${RST}"
echo -e "  ${W}sudo m7hunter --dashboard${RST}"
echo ""
echo -e "  ${C}More options:${RST}"
echo -e "  ${W}--fast              ${RST}Fast scan (Phase 1 only)"
echo -e "  ${W}--stealth           ${RST}Slow + Tor-routed"
echo -e "  ${W}--ws                ${RST}WebSocket testing"
echo -e "  ${W}--proto-pollution   ${RST}Prototype pollution (Node.js)"
echo -e "  ${W}--no-double-verify  ${RST}Faster scan (more FPs)"
echo -e "  ${W}--resume            ${RST}Resume interrupted scan"
echo ""
echo -e "  ${B}github.com/httpsm7 | MilkyWay Intelligence${RST}"
echo ""
