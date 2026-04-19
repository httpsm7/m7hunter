#!/usr/bin/env bash
# M7Hunter V8 Installer
# MilkyWay Intelligence | Author: Sharlix
set -e
G='\033[92m';Y='\033[93m';C='\033[96m';R='\033[91m';RST='\033[0m'
[ "$EUID" -ne 0 ] && { echo -e "${R}Run as root: sudo bash install_v8.sh${RST}"; exit 1; }
exists(){ command -v "$1" &>/dev/null; }

echo -e "${C}M7Hunter V8 — Installing...${RST}"
apt-get update -qq

for pkg in nmap sqlmap tor proxychains4 golang-go ruby ruby-dev jq curl git python3 python3-pip chromium; do
  exists "$pkg" && echo -e "${G}[✓]${RST} $pkg" || apt-get install -y "$pkg" -qq 2>/dev/null && echo -e "${G}[↓]${RST} $pkg"
done

export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"
grep -q 'GOPATH' /root/.bashrc 2>/dev/null || {
  echo 'export GOPATH=$HOME/go' >> /root/.bashrc
  echo 'export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin' >> /root/.bashrc
}

for tool in \
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" \
  "github.com/projectdiscovery/httpx/cmd/httpx@latest" \
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" \
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest" \
  "github.com/projectdiscovery/katana/cmd/katana@latest" \
  "github.com/hahwul/dalfox/v2@latest" \
  "github.com/tomnomnom/waybackurls@latest" \
  "github.com/lc/gau/v2/cmd/gau@latest" \
  "github.com/tomnomnom/gf@latest" \
  "github.com/tomnomnom/qsreplace@latest" \
  "github.com/tomnomnom/anew@latest" \
  "github.com/ffuf/ffuf/v2@latest" \
  "github.com/Emoe/kxss@latest" \
  "github.com/PentestPanic/subzy@latest" \
  "github.com/hakluke/hakrawler@latest"; do
  name=$(echo "$tool" | awk -F'/' '{print $(NF)}' | cut -d@ -f1)
  echo -ne "${Y}[↓]${RST} $name... "
  go install "$tool" >/dev/null 2>&1 && echo -e "${G}done${RST}" || echo -e "${Y}skip${RST}"
done

pip3 install --break-system-packages --quiet "httpx[http2]" playwright aiofiles websockets requests wafw00f arjun cloud-enum 2>/dev/null || true
playwright install chromium --with-deps 2>/dev/null || echo -e "${Y}Playwright: manual install needed${RST}"
gem install wpscan --quiet 2>/dev/null || true

# Ollama
if ! exists ollama; then
  echo -e "${C}Installing Ollama...${RST}"
  curl -fsSL https://ollama.com/install.sh | sh 2>/dev/null
  echo -e "${G}Ollama installed — run: ollama pull llama3${RST}"
else
  echo -e "${G}[✓]${RST} Ollama"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cat > /usr/local/bin/m7hunter << WRAP
#!/usr/bin/env bash
exec python3 "${SCRIPT_DIR}/m7hunter.py" "\$@"
WRAP
chmod +x /usr/local/bin/m7hunter

mkdir -p "$HOME/.m7hunter/sessions" "$HOME/.m7hunter/audit"
echo ""
echo -e "${G}✅ M7Hunter V8 installed!${RST}"
echo ""
echo -e "  ${C}Setup Ollama AI:${RST}"
echo -e "  ${Y}ollama serve &${RST}"
echo -e "  ${Y}ollama pull llama3${RST}"
echo ""
echo -e "  ${C}Quick Start:${RST}"
echo -e "  ${Y}sudo m7hunter -u target.com --deep --cookie 'session=x'${RST}"
echo -e "  ${Y}sudo m7hunter --dashboard${RST}  # then open http://localhost:8719"
