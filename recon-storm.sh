#!/bin/bash
# recon-storm — Automated Reconnaissance Pipeline
# Author: Abdulelah Al-shalahi (@0xAlshalahi)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

banner() {
    echo -e "${RED}"
    echo "  ╦═╗╔═╗╔═╗╔═╗╔╗╔  ╔═╗╔╦╗╔═╗╦═╗╔╦╗"
    echo "  ╠╦╝║╣ ║  ║ ║║║║  ╚═╗ ║ ║ ║╠╦╝║║║"
    echo "  ╩╚═╚═╝╚═╝╚═╝╝╚╝  ╚═╝ ╩ ╚═╝╩╚═╩ ╩"
    echo -e "${NC}"
    echo -e "${CYAN}  Automated Recon Pipeline — @0xAlshalahi${NC}"
    echo ""
}

usage() {
    echo "Usage: $0 -d <domain> [-m <module>] [-w <wordlist>] [-l <list>] [-t <threads>]"
    echo ""
    echo "Options:"
    echo "  -d    Target domain"
    echo "  -l    File containing list of domains"
    echo "  -m    Module: all|subs|tech|wayback|js|dirs|ports (default: all)"
    echo "  -w    Custom wordlist for directory brute-forcing"
    echo "  -t    Thread count (default: 10)"
    echo "  -o    Output directory (default: ./target.com/)"
    echo "  -h    Show this help"
    exit 1
}

check_tool() {
    if ! command -v "$1" &>/dev/null; then
        echo -e "${RED}[!] Missing: $1 — run install.sh first${NC}"
        return 1
    fi
    return 0
}

check_dependencies() {
    local missing=0
    for tool in subfinder dnsx httpx waybackurls gau gf ffuf nmap jq curl; do
        check_tool "$tool" || ((missing++))
    done
    if [ "$missing" -gt 0 ]; then
        echo -e "${YELLOW}[!] $missing tools missing. Some modules may not work.${NC}"
    fi
}

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
info() { echo -e "${CYAN}[*]${NC} $1"; }

module_subdomains() {
    local domain=$1 dir=$2
    mkdir -p "$dir/subdomains"
    log "Subdomain enumeration for $domain"

    info "Running subfinder..."
    subfinder -d "$domain" -all -silent > "$dir/subdomains/subfinder.txt" 2>/dev/null &

    info "Querying crt.sh..."
    curl -s "https://crt.sh/?q=%25.$domain&output=json" 2>/dev/null \
        | jq -r '.[].name_value' 2>/dev/null \
        | sed 's/\*\.//g' | sort -u > "$dir/subdomains/crt.txt" &

    if command -v amass &>/dev/null; then
        info "Running amass (passive)..."
        amass enum -passive -d "$domain" -o "$dir/subdomains/amass.txt" 2>/dev/null &
    fi

    if command -v assetfinder &>/dev/null; then
        assetfinder --subs-only "$domain" > "$dir/subdomains/assetfinder.txt" 2>/dev/null &
    fi

    wait
    cat "$dir/subdomains/"*.txt 2>/dev/null | sort -u > "$dir/subdomains/all.txt"
    local count=$(wc -l < "$dir/subdomains/all.txt")
    log "Found $count unique subdomains"

    info "Resolving DNS..."
    cat "$dir/subdomains/all.txt" | dnsx -silent -a -resp -o "$dir/subdomains/resolved.txt" 2>/dev/null

    info "Probing alive hosts..."
    cat "$dir/subdomains/all.txt" | httpx -silent -status-code -title -tech-detect \
        -content-length -web-server -follow-redirects \
        -json -o "$dir/tech/httpx.json" 2>/dev/null
    cat "$dir/tech/httpx.json" 2>/dev/null | jq -r '.url' > "$dir/subdomains/alive.txt"
    local alive=$(wc -l < "$dir/subdomains/alive.txt")
    log "Alive hosts: $alive"
}

module_tech() {
    local domain=$1 dir=$2
    mkdir -p "$dir/tech"
    log "Technology fingerprinting"

    if [ ! -f "$dir/subdomains/alive.txt" ]; then
        warn "No alive hosts found. Run subs module first."
        return
    fi

    info "Collecting headers..."
    while IFS= read -r url; do
        echo "=== $url ===" >> "$dir/tech/headers.txt"
        curl -sI "$url" --max-time 10 >> "$dir/tech/headers.txt" 2>/dev/null
        echo "" >> "$dir/tech/headers.txt"
    done < "$dir/subdomains/alive.txt"

    info "Extracting technology stack..."
    cat "$dir/tech/httpx.json" 2>/dev/null | jq -r \
        '[.url, .webserver // "N/A", (.tech // [] | join(","))] | @tsv' \
        > "$dir/tech/stack.tsv"

    log "Tech fingerprinting complete"
}

module_wayback() {
    local domain=$1 dir=$2
    mkdir -p "$dir/wayback" "$dir/gf"
    log "Web archive intelligence"

    info "Collecting from waybackurls..."
    echo "$domain" | waybackurls > "$dir/wayback/waybackurls.txt" 2>/dev/null &

    info "Collecting from gau..."
    echo "$domain" | gau --subs --threads 5 > "$dir/wayback/gau.txt" 2>/dev/null &

    wait
    cat "$dir/wayback/"*.txt 2>/dev/null | sort -u > "$dir/wayback/all_urls.txt"
    local count=$(wc -l < "$dir/wayback/all_urls.txt")
    log "Archived URLs: $count"

    info "Classifying with gf patterns..."
    for pattern in xss sqli ssrf redirect lfi rce idor ssti interestingparams; do
        cat "$dir/wayback/all_urls.txt" | gf "$pattern" > "$dir/gf/${pattern}.txt" 2>/dev/null
    done

    info "Extracting file types..."
    grep -iE "\.js($|\?)" "$dir/wayback/all_urls.txt" | sort -u > "$dir/wayback/js_files.txt"
    grep -iE "\.json($|\?)" "$dir/wayback/all_urls.txt" | sort -u > "$dir/wayback/json_endpoints.txt"
    grep -iE "\.(env|bak|sql|log|conf|yml|xml)" "$dir/wayback/all_urls.txt" | sort -u > "$dir/wayback/sensitive_files.txt"
    grep -iE "(api|graphql|v[0-9]|swagger)" "$dir/wayback/all_urls.txt" | sort -u > "$dir/wayback/api_endpoints.txt"
    grep "?" "$dir/wayback/all_urls.txt" | sort -u > "$dir/wayback/parameterized.txt"

    log "URL classification complete"
}

module_js() {
    local domain=$1 dir=$2
    mkdir -p "$dir/js/files"
    log "JavaScript analysis"

    if [ ! -f "$dir/wayback/js_files.txt" ]; then
        warn "No JS files found. Run wayback module first."
        return
    fi

    local count=$(wc -l < "$dir/wayback/js_files.txt")
    info "Downloading $count JS files..."

    head -100 "$dir/wayback/js_files.txt" | while IFS= read -r url; do
        fname=$(echo "$url" | md5sum | awk '{print $1}').js
        curl -s "$url" -o "$dir/js/files/$fname" --max-time 10
    done

    info "Extracting secrets..."
    grep -rnE "(api[_-]?key|api[_-]?secret|access[_-]?token|bearer|password|secret|private[_-]?key|AWS_|AKIA)" \
        "$dir/js/files/" 2>/dev/null > "$dir/js/secrets.txt"

    grep -rnE "https?://[a-zA-Z0-9._-]*\.(internal|local|dev|staging|test)" \
        "$dir/js/files/" 2>/dev/null >> "$dir/js/secrets.txt"

    local found=$(wc -l < "$dir/js/secrets.txt")
    log "Potential secrets found: $found"
}

module_dirs() {
    local domain=$1 dir=$2 wordlist=$3
    mkdir -p "$dir/dirs"
    log "Directory brute-forcing"

    if [ -z "$wordlist" ]; then
        for wl in \
            /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
            /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
            /usr/share/dirb/wordlists/common.txt; do
            [ -f "$wl" ] && wordlist="$wl" && break
        done
    fi

    if [ -z "$wordlist" ]; then
        warn "No wordlist found. Specify with -w flag."
        return
    fi

    info "Using wordlist: $wordlist"
    local target="https://$domain"

    ffuf -u "${target}/FUZZ" -w "$wordlist" \
        -mc 200,301,302,403 -ac -rate 10 \
        -o "$dir/dirs/ffuf_results.json" -of json 2>/dev/null

    log "Directory brute-force complete"
}

module_ports() {
    local domain=$1 dir=$2
    mkdir -p "$dir/ports"
    log "Port scanning"

    if [ ! -f "$dir/subdomains/resolved.txt" ]; then
        info "Resolving $domain directly..."
        local ip=$(dig +short "$domain" | head -1)
        echo "$ip" > "$dir/ports/ips.txt"
    else
        awk '{print $NF}' "$dir/subdomains/resolved.txt" | sort -u > "$dir/ports/ips.txt"
    fi

    info "Running nmap service detection..."
    nmap -sV --top-ports 1000 -T3 -iL "$dir/ports/ips.txt" \
        -oN "$dir/ports/nmap_services.txt" 2>/dev/null

    log "Port scan complete"
}

generate_report() {
    local domain=$1 dir=$2
    log "Generating report..."

    {
        echo "═══════════════════════════════════════════"
        echo "  RECON-STORM REPORT — $domain"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Researcher: Abdulelah Al-shalahi"
        echo "═══════════════════════════════════════════"
        echo ""

        echo "[SUBDOMAINS]"
        [ -f "$dir/subdomains/all.txt" ] && echo "  Total: $(wc -l < "$dir/subdomains/all.txt")"
        [ -f "$dir/subdomains/alive.txt" ] && echo "  Alive: $(wc -l < "$dir/subdomains/alive.txt")"
        echo ""

        echo "[ARCHIVED URLS]"
        [ -f "$dir/wayback/all_urls.txt" ] && echo "  Total: $(wc -l < "$dir/wayback/all_urls.txt")"
        [ -f "$dir/wayback/parameterized.txt" ] && echo "  With params: $(wc -l < "$dir/wayback/parameterized.txt")"
        echo ""

        echo "[GF PATTERNS]"
        for f in "$dir/gf/"*.txt; do
            [ -f "$f" ] && echo "  $(basename "$f" .txt): $(wc -l < "$f")"
        done
        echo ""

        echo "[POTENTIAL SECRETS]"
        [ -f "$dir/js/secrets.txt" ] && echo "  Found: $(wc -l < "$dir/js/secrets.txt")"
        echo ""

        echo "[SENSITIVE FILES]"
        [ -f "$dir/wayback/sensitive_files.txt" ] && cat "$dir/wayback/sensitive_files.txt" | head -20
        echo ""

        echo "═══════════════════════════════════════════"
        echo "  Report generated by recon-storm"
        echo "═══════════════════════════════════════════"
    } > "$dir/report.txt"

    log "Report saved: $dir/report.txt"
}

# ── Main ──

DOMAIN=""
DOMAINS_FILE=""
MODULE="all"
WORDLIST=""
THREADS=10
OUTDIR=""

while getopts "d:l:m:w:t:o:h" opt; do
    case $opt in
        d) DOMAIN="$OPTARG" ;;
        l) DOMAINS_FILE="$OPTARG" ;;
        m) MODULE="$OPTARG" ;;
        w) WORDLIST="$OPTARG" ;;
        t) THREADS="$OPTARG" ;;
        o) OUTDIR="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

banner

if [ -z "$DOMAIN" ] && [ -z "$DOMAINS_FILE" ]; then
    usage
fi

check_dependencies

run_recon() {
    local domain=$1
    local dir="${OUTDIR:-$domain}"
    mkdir -p "$dir"/{subdomains,tech,wayback,gf,js,dirs,ports}

    info "Target: $domain"
    info "Output: $dir/"
    echo ""

    case $MODULE in
        all)
            module_subdomains "$domain" "$dir"
            module_tech "$domain" "$dir"
            module_wayback "$domain" "$dir"
            module_js "$domain" "$dir"
            module_dirs "$domain" "$dir" "$WORDLIST"
            module_ports "$domain" "$dir"
            ;;
        subs)    module_subdomains "$domain" "$dir" ;;
        tech)    module_tech "$domain" "$dir" ;;
        wayback) module_wayback "$domain" "$dir" ;;
        js)      module_js "$domain" "$dir" ;;
        dirs)    module_dirs "$domain" "$dir" "$WORDLIST" ;;
        ports)   module_ports "$domain" "$dir" ;;
        *)       warn "Unknown module: $MODULE"; usage ;;
    esac

    generate_report "$domain" "$dir"
    echo ""
    log "Recon complete for $domain"
}

if [ -n "$DOMAIN" ]; then
    run_recon "$DOMAIN"
elif [ -n "$DOMAINS_FILE" ]; then
    while IFS= read -r domain; do
        [ -z "$domain" ] && continue
        run_recon "$domain"
        echo ""
    done < "$DOMAINS_FILE"
fi
