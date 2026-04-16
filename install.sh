#!/bin/bash
# recon-storm installer — installs all required tools
echo "[*] Installing recon-storm dependencies..."

command -v go &>/dev/null || { echo "[!] Go is required. Install from https://go.dev/dl/"; exit 1; }

echo "[*] Installing Go tools..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/gf@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/ffuf/ffuf/v2@latest

echo "[*] Installing gf patterns..."
mkdir -p ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-patterns 2>/dev/null
cp /tmp/gf-patterns/*.json ~/.gf/ 2>/dev/null

echo "[+] Installation complete. Ensure ~/go/bin is in your PATH."
