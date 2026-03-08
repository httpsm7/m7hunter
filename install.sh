#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#   M7HUNTER v2.0 — One-Click Installer
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
  ══════════════════════

  M7HUNTER v2.0 — One-Click Installer
  Made by MilkyWay Intelligence | Author: Sharlix
  
EOF
}

log_ok()   { echo -e "${G}[✓]${RST} $1"; }
log_info() { echo -e "${C}[*]${RST} $1"; }
log_warn() { echo -e "${Y}[!]${RST} $1"; }
log_err()  { echo -e "${R}[✗]${RST} $1"; }
log_sec()  { echo -e "\n${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"; echo -e "${B}  ▶  ${W}$1${RST}"; echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}\n"; }

# ── Root check ────────────────────────────────────────────────────
[ "$EUID" -ne 0 ] && { log_err "Run as root: sudo bash install.sh"; exit 1; }

# ── Tool exists check (PATH + common dirs) ────────────────────────
tool_exists(){
    command -v "$1" &>/dev/null && return 0
    for d in /usr/bin /usr/local/bin /usr/local/go/bin \
              "$HOME/go/bin" "$HOME/.local/bin" /snap/bin; do
        [ -x "$d/$1" ] && return 0
    done
    return 1
}

# ── APT ───────────────────────────────────────────────────────────
install_apt(){
    log_sec "APT Tools"
    apt-get update -qq 2>/dev/null

    APT_PKGS="nmap masscan sqlmap tor proxychains4 massdns amass jq \
              curl git python3 python3-pip dnsutils ruby ruby-dev \
              build-essential libcurl4-openssl-dev make gcc"

    for pkg in $APT_PKGS; do
        bin="$pkg"
        [ "$pkg" = "dnsutils" ]    && bin="dig"
        [ "$pkg" = "python3-pip" ] && bin="pip3"
        [ "$pkg" = "ruby-dev" ]    && bin="ruby"
        [ "$pkg" = "build-essential" ] && bin="gcc"
        [ "$pkg" = "libcurl4-openssl-dev" ] && bin="curl"
        [ "$pkg" = "make" ] && bin="make"
        if tool_exists "$bin"; then
            log_ok "$pkg — already installed"
        else
            log_info "Installing $pkg..."
            apt-get install -y "$pkg" -qq 2>/dev/null && log_ok "$pkg done" \
                || log_warn "$pkg failed"
        fi
    done
}

# ── Go ────────────────────────────────────────────────────────────
install_go(){
    log_sec "Go Language"
    if tool_exists go; then
        log_ok "Go already installed: $(go version 2>/dev/null | awk '{print $3}')"
    else
        log_info "Installing Go..."
        apt-get install -y golang-go -qq 2>/dev/null || snap install go --classic 2>/dev/null
    fi
    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"
    grep -q 'GOPATH' /root/.bashrc 2>/dev/null || {
        echo 'export GOPATH=$HOME/go' >> /root/.bashrc
        echo 'export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin' >> /root/.bashrc
    }
    log_ok "Go path configured"
}

# ── Go tools ──────────────────────────────────────────────────────
install_go_tools(){
    log_sec "Go Security Tools"
    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"

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
    )

    for tool in "${!GOTOOLS[@]}"; do
        if tool_exists "$tool"; then
            log_ok "$tool — already installed"
        else
            log_info "Installing $tool..."
            go install -v "${GOTOOLS[$tool]}" &>/dev/null \
                && log_ok "$tool installed" \
                || log_warn "$tool failed"
        fi
    done
}

# ── Python packages ───────────────────────────────────────────────
install_python(){
    log_sec "Python Packages"
    PKGS="requests stem colorama tqdm rich arjun"
    pip3 install --break-system-packages --quiet $PKGS 2>/dev/null \
    || pip3 install --quiet $PKGS 2>/dev/null
    log_ok "Python packages installed"
}

# ── WPScan ────────────────────────────────────────────────────────
install_wpscan(){
    log_sec "WPScan"
    if tool_exists wpscan; then log_ok "WPScan already installed"
    else
        log_info "Installing WPScan..."
        gem install wpscan 2>/dev/null && log_ok "WPScan installed" \
            || log_warn "WPScan failed"
    fi
}

# ── SecLists ──────────────────────────────────────────────────────
install_seclists(){
    log_sec "SecLists Wordlists"
    if [ -d "/usr/share/seclists" ]; then
        log_ok "SecLists already installed"
    else
        log_info "Installing SecLists (this may take time)..."
        apt-get install -y seclists -qq 2>/dev/null \
        || git clone --depth 1 https://github.com/danielmiessler/SecLists \
               /usr/share/seclists 2>/dev/null
        log_ok "SecLists installed"
    fi
}

# ── GF Patterns ───────────────────────────────────────────────────
install_gf_patterns(){
    log_sec "GF Patterns"
    GF_DIR="$HOME/.gf"
    if [ -d "$GF_DIR" ] && ls "$GF_DIR"/*.json &>/dev/null 2>&1; then
        log_ok "GF patterns already present"
        return
    fi
    mkdir -p "$GF_DIR"
    git clone --quiet https://github.com/1ndianl33t/Gf-Patterns /tmp/gfp 2>/dev/null \
        && cp /tmp/gfp/*.json "$GF_DIR/" 2>/dev/null && log_ok "1ndianl33t patterns added"
    git clone --quiet https://github.com/tomnomnom/gf /tmp/gfs 2>/dev/null \
        && cp /tmp/gfs/examples/*.json "$GF_DIR/" 2>/dev/null && log_ok "tomnomnom patterns added"
}

# ── Nuclei templates ──────────────────────────────────────────────
update_nuclei(){
    log_sec "Nuclei Templates"
    tool_exists nuclei && nuclei -update-templates -silent 2>/dev/null \
        && log_ok "Templates updated" || log_warn "nuclei not found"
}

# ── Configure Tor ─────────────────────────────────────────────────
configure_tor(){
    log_sec "Tor Configuration"
    cat > /etc/tor/torrc << 'TORRC'
SocksPort 9050
ControlPort 9051
HashedControlPassword 16:E600ADC90A2E3F9D8F0A4D24BCFF62C8F6C1E9B3D2A1F0E9C8B7A6D5
DataDirectory /var/lib/tor
TORRC
    systemctl enable tor 2>/dev/null; systemctl restart tor 2>/dev/null
    sleep 2
    if systemctl is-active --quiet tor 2>/dev/null; then
        log_ok "Tor service running"
    else
        service tor start 2>/dev/null && log_ok "Tor started" || log_warn "Start tor manually: service tor start"
    fi
}

# ── ProxyChains ───────────────────────────────────────────────────
configure_proxychains(){
    for f in /etc/proxychains4.conf /etc/proxychains.conf; do
        [ -f "$f" ] && {
            grep -q "127.0.0.1 9050" "$f" || echo "socks5 127.0.0.1 9050" >> "$f"
            sed -i 's/^#quiet_mode/quiet_mode/' "$f" 2>/dev/null
            log_ok "ProxyChains → Tor SOCKS5 configured"
            break
        }
    done
}

# ── Global m7hunter command ───────────────────────────────────────
install_command(){
    log_sec "M7Hunter Command"
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cat > /usr/local/bin/m7hunter << WRAP
#!/usr/bin/env bash
exec python3 "${SCRIPT_DIR}/m7hunter.py" "\$@"
WRAP
    chmod +x /usr/local/bin/m7hunter
    log_ok "Global command installed: m7hunter"
}

# ── Results dir ───────────────────────────────────────────────────
setup_dirs(){
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    mkdir -p "${SCRIPT_DIR}/results"
    log_ok "Results directory ready"
}

# ── Summary ───────────────────────────────────────────────────────
print_summary(){
    echo ""
    echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
    echo -e "${G}  ✅  M7Hunter v2.0 — Installation Complete!${RST}"
    echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
    echo ""
    echo -e "  ${C}Quick Examples:${RST}"
    echo -e "  ${W}sudo m7hunter -u example.com --quick${RST}"
    echo -e "  ${W}sudo m7hunter -u example.com --deep --tor${RST}"
    echo -e "  ${W}sudo m7hunter -f targets.txt --stealth${RST}"
    echo -e "  ${W}sudo m7hunter -u example.com --custom --xss --sqli --nuclei${RST}"
    echo ""
    echo -e "  ${C}Verify tools:${RST}"
    echo -e "  ${W}sudo m7hunter --install${RST}"
    echo ""
}

# ── MAIN ──────────────────────────────────────────────────────────
clear
print_banner
log_sec "Starting M7Hunter Installation"
install_apt
install_go
install_go_tools
install_python
install_wpscan
install_seclists
install_gf_patterns
update_nuclei
configure_tor
configure_proxychains
install_command
setup_dirs
print_summary
