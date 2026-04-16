<h1 align="center">recon-storm</h1>
<h3 align="center">Automated Reconnaissance Pipeline for Bug Bounty & Red Team</h3>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Bash-green?style=for-the-badge&logo=gnubash&logoColor=white" />
  <img src="https://img.shields.io/badge/Phase-Reconnaissance-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" />
</p>

---

## Overview

**recon-storm** is a modular reconnaissance automation framework written in Bash. It chains together best-in-class tools into a single pipeline that takes a target domain and produces organized, analysis-ready output in minutes.

Built from real-world bug bounty and red team engagement workflows.

## Features

- **Subdomain Enumeration** — Multi-source passive collection (subfinder, amass, assetfinder, crt.sh)
- **DNS Resolution** — Bulk resolution with dnsx, CNAME tracking for subdomain takeover detection
- **HTTP Probing** — Alive host detection with full tech fingerprinting via httpx
- **Web Archive Mining** — Wayback Machine + GAU URL collection with gf pattern classification
- **JavaScript Analysis** — JS file collection and automated secret extraction
- **Directory Brute-Force** — Targeted ffuf scans with smart wordlist selection
- **Port Scanning** — Service discovery with nmap on non-standard ports
- **Organized Output** — Everything sorted into a clean directory structure per target

## Installation

```bash
git clone https://github.com/0xAlshalahi/recon-storm.git
cd recon-storm
chmod +x recon-storm.sh install.sh
./install.sh   # Installs required Go/Python tools
```

## Usage

```bash
# Full recon pipeline
./recon-storm.sh -d target.com

# Subdomain enumeration only
./recon-storm.sh -d target.com -m subs

# Wayback + JS analysis only
./recon-storm.sh -d target.com -m wayback

# With custom wordlist for directory brute-force
./recon-storm.sh -d target.com -w /path/to/wordlist.txt

# Multiple targets from file
./recon-storm.sh -l targets.txt
```

## Output Structure

```
target.com/
├── subdomains/
│   ├── all.txt              # Merged & deduplicated subdomains
│   ├── resolved.txt         # DNS-resolved with IPs
│   └── alive.txt            # HTTP-alive hosts
├── tech/
│   ├── httpx.json           # Full fingerprinting data
│   └── headers.txt          # Raw HTTP headers
├── wayback/
│   ├── all_urls.txt         # Archived URLs
│   ├── parameterized.txt    # URLs with GET parameters
│   ├── js_files.txt         # JavaScript file URLs
│   ├── api_endpoints.txt    # API paths
│   └── sensitive_files.txt  # Config/backup files
├── gf/
│   ├── sqli.txt             # SQL injection candidates
│   ├── xss.txt              # XSS candidates
│   ├── ssrf.txt             # SSRF candidates
│   ├── lfi.txt              # LFI candidates
│   └── idor.txt             # IDOR candidates
├── js/
│   ├── files/               # Downloaded JS files
│   └── secrets.txt          # Extracted secrets/keys
├── ports/
│   └── nmap_services.txt    # Service versions
└── report.txt               # Executive summary
```

## Required Tools

| Tool | Purpose | Install |
|------|---------|---------|
| subfinder | Subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| amass | Subdomain enumeration | `go install github.com/owasp-amass/amass/v4/...@master` |
| dnsx | DNS resolution | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| httpx | HTTP probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| waybackurls | Archive mining | `go install github.com/tomnomnom/waybackurls@latest` |
| gau | URL aggregation | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| gf | Pattern matching | `go install github.com/tomnomnom/gf@latest` |
| ffuf | Directory brute-force | `go install github.com/ffuf/ffuf/v2@latest` |
| nmap | Port scanning | `apt install nmap` |
| jq | JSON parsing | `apt install jq` |

## Author

**Abdulelah Al-shalahi** — [@0xAlshalahi](https://github.com/0xAlshalahi)

## License

MIT
