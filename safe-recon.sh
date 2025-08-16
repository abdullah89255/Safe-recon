#!/usr/bin/env bash
# safe-recon.sh — Consent-only reconnaissance helper for bug bounty and authorized testing
#
# Designed for bug bounty hunters or site owners to safely inventory web-facing technologies.
# Defaults to passive/light checks and requires explicit authorization confirmation.
#
# IMPORTANT: Use only on in-scope assets for bug bounty programs or assets you own/have permission to test.
# Follow program rules and respect robots.txt. Authors accept no liability for misuse.
#
# Features:
#  - Passive tech fingerprinting (HTTP headers, meta tags, asset hints)
#  - DNS inventory (A/AAAA/CNAME/TXT/MX/NS)
#  - Subdomain discovery via subfinder (passive APIs)
#  - Optional active scans via nmap, nikto, nuclei (off by default; rate-limited)
#  - Outputs to /out folder with TXT/CSV and HTML summary
#
# Dependencies (install on Kali: sudo apt install curl dnsutils jq whatweb subfinder nmap nikto nuclei):
#  curl, dig, jq, whatweb, subfinder, nmap, nikto, nuclei
#  For wappalyzer: npm install -g wappalyzer
#
# Usage example:
#  sudo ./safe-recon.sh --i-own-this -t testphp.vulnweb.com --active --with-nikto --with-nuclei
#  echo -e "testphp.vulnweb.com\nsub.example.com" > targets.txt; sudo ./safe-recon.sh --i-own-this -l targets.txt
#

set -uo pipefail
IFS=$'\n\t'

VERSION="1.0.6"  # Bumped for syntax fix
SCRIPT_NAME="safe-recon.sh"

# ----- defaults -----
OUTDIR=""
TARGETS=()
OWNERSHIP_CONFIRMED=false
ACTIVE=false
FULL_PORTS=false
WITH_NIKTO=false
WITH_NUCLEI=false
DELAY=0
RATE_LIMIT_NUCLEI=5
NMAP_TOP_PORTS=100

usage() {
  cat <<USAGE
${SCRIPT_NAME} v${VERSION}
Safe recon for bug bounty or authorized domains.

Usage:
  ${SCRIPT_NAME} --i-own-this -t example.com [options]
  ${SCRIPT_NAME} --i-own-this -l targets.txt [options]

Required:
  --i-own-this              Confirm you have authorization or target is in-scope.

Target selection (choose one):
  -t, --target DOMAIN       Single domain (e.g., example.com)
  -l, --list FILE           File with one domain per line

Output:
  -o, --out DIR             Output directory (default: ./out-YYYYmmdd-HHMMSS)

Safety / scope controls:
  --active                  Enable light active checks (nmap top ${NMAP_TOP_PORTS})
  --full-ports              With --active, scan all TCP ports (-p-)
  --with-nikto              Include nikto (active HTTP checks)
  --with-nuclei             Include nuclei (HTTP CVE templates), rate-limited
  --delay SEC               Sleep between targets (default: 0)

Other:
  -h, --help                Show this help
  -v, --version             Show version

Notes:
  - Passive mode by default. Active scans need explicit flags.
  - For bug bounty: Ensure targets are in scope; respect rate limits.
  - Install dependencies: sudo apt install curl dnsutils jq whatweb subfinder nmap nikto nuclei
USAGE
}

log()   { printf "[%s] %s\n" "$(date '+%F %T')" "$*"; }
warn()  { printf "[%s] [WARN] %s\n" "$(date '+%F %T')" "$*" >&2; }
fail()  { printf "[%s] [FAIL] %s\n" "$(date '+%F %T')" "$*" >&2; exit 1; }

check_dependencies() {
  log "Checking dependencies..."
  local missing=0
  for tool in curl dig jq whatweb wappalyzer subfinder nmap nikto nuclei; do
    command -v "$tool" >/dev/null 2>&1 || { warn "$tool missing - install with 'sudo apt install $tool' or 'npm install -g wappalyzer'"; ((missing++)); }
  done
  [[ $missing -eq 9 ]] && warn "No tools installed; minimal output will be generated"
  [[ $missing -eq 0 ]] && log "All dependencies present"
}

validate_target() {
  local domain="$1"
  log "Validating domain resolution for $domain"
  if command -v dig >/dev/null 2>&1; then
    if dig +short "$domain" >/dev/null 2>&1; then
      log "$domain resolves successfully"
      return 0
    else
      warn "$domain does not resolve (DNS failure)"
      return 1
    fi
  else
    warn "dig not installed; cannot validate $domain"
    return 0
  fi
}

mkoutdir() {
  if [[ -z "$OUTDIR" ]]; then
    OUTDIR="out-$(date '+%Y%m%d-%H%M%S')"
  fi
  mkdir -p "$OUTDIR" && log "Created output directory: $OUTDIR" || fail "Cannot create $OUTDIR"
}

parse_args() {
  log "Parsing arguments..."
  local argv=("$@")
  local i=0
  while [[ $i -lt ${#argv[@]} ]]; do
    case "${argv[$i]}" in
      --i-own-this) OWNERSHIP_CONFIRMED=true ;;
      -t|--target)
        ((i++))
        if [[ "${argv[$i]}" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
          TARGETS+=("${argv[$i]}")
        else
          fail "Invalid domain: ${argv[$i]} (use valid domain or -l for multiple)"
        fi
        ;;
      -l|--list)
        ((i++))
        if [[ -r "${argv[$i]}" ]]; then
          mapfile -t TARGETS < <(grep -vE '^(#|\s*$)' "${argv[$i]}" | grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
          [[ ${#TARGETS[@]} -gt 0 ]] || fail "No valid domains in ${argv[$i]}"
        else
          fail "Cannot read file ${argv[$i]}"
        fi
        ;;
      -o|--out) ((i++)); OUTDIR="${argv[$i]}" ;;
      --active) ACTIVE=true ;;
      --full-ports) FULL_PORTS=true ;;
      --with-nikto) WITH_NIKTO=true ;;
      --with-nuclei) WITH_NUCLEI=true ;;
      --delay) ((i++)); DELAY="${argv[$i]}" ;;
      -h|--help) usage; exit 0 ;;
      -v|--version) echo "$VERSION"; exit 0 ;;
      *) fail "Unknown argument: ${argv[$i]}" ;;
    esac
    ((i++))
  done
  $OWNERSHIP_CONFIRMED || fail "Must confirm with --i-own-this"
  [[ ${#TARGETS[@]} -gt 0 ]] || fail "No valid targets provided (use -t or -l)"
  log "Targets: ${TARGETS[*]}"
}

normalize_domain() {
  local d="$1"
  d="${d#http://}"
  d="${d#https://}"
  d="${d%%/*}"
  echo "$d"
}

http_url_guess() {
  local d="$1"
  echo "https://$d"
}

fingerprint_http() {
  local domain="$1"; local dstdir="$2"
  mkdir -p "$dstdir"
  if ! command -v curl >/dev/null 2>&1; then
    warn "$domain: curl missing; skipping HTTP fingerprinting"
    echo "curl not installed" > "$dstdir/http_headers.txt"
    return
  fi
  local url=$(http_url_guess "$domain")
  local headers="$dstdir/http_headers.txt"
  local errlog="$dstdir/http_err.log"
  log "$domain: Fetching HTTP headers from $url"
  if ! curl -ksSIL --max-time 20 -A "Mozilla/5.0" "$url" -o "$headers" 2>"$errlog"; then
    warn "$domain: HTTPS headers failed; trying HTTP"
    url="http://$domain"
    curl -ksSIL --max-time 20 -A "Mozilla/5.0" "$url" -o "$headers" 2>>"$errlog" || warn "$domain: HTTP headers also failed; check $errlog"
  fi
  [[ -s "$headers" ]] || echo "No headers retrieved" > "$headers"

  log "$domain: Fetching body for meta/assets"
  local body=$(mktemp)
  if curl -ksSL --max-time 30 -A "Mozilla/5.0" "$url" -o "$body" 2>>"$errlog"; then
    grep -Eoi '<meta[^>]+(generator|powered|framework)[^>]*>' "$body" | sed 's/\s\+/ /g' > "$dstdir/meta_tags.txt" || echo "No meta tags found" > "$dstdir/meta_tags.txt"
    grep -Eoi '<script[^>]+src=[^>]+>' "$body" | sed 's/\s\+/ /g' > "$dstdir/assets_js.txt" || echo "No JS assets found" > "$dstdir/assets_js.txt"
    grep -Eoi '<link[^>]+(rel|href)=[^>]+>' "$body" | sed 's/\s\+/ /g' > "$dstdir/assets_css.txt" || echo "No CSS assets found" > "$dstdir/assets_css.txt"
  else
    warn "$domain: Body fetch failed; check $errlog"
    echo "Failed to fetch body" > "$dstdir/meta_tags.txt"
    echo "Failed to fetch body" > "$dstdir/assets_js.txt"
    echo "Failed to fetch body" > "$dstdir/assets_css.txt"
  fi
  rm -f "$body"

  log "$domain: Checking cookies"
  curl -ksSI -A "Mozilla/5.0" "$url" 2>/dev/null | awk -F": " '/^Set-Cookie:/ {print $2}' > "$dstdir/cookies.txt" || echo "No cookies found" > "$dstdir/cookies.txt"

  log "$domain: Generating tech hints"
  local tech="$dstdir/tech_hints.txt"
  {
    awk -F": " '/^Server:/ {print "server=>"$2}' "$headers" || echo "server=>none"
    awk -F": " '/^X-Powered-By:/ {print "x-powered-by=>"$2}' "$headers" || echo "x-powered-by=>none"
    grep -E 'wp-content|wp-includes' "$dstdir/assets_js.txt" >/dev/null 2>&1 && echo "cms=>wordpress"
    grep -E 'drupal|/sites/all/' "$dstdir/assets_js.txt" >/dev/null 2>&1 && echo "cms=>drupal"
    grep -E -i 'joomla' "$dstdir/meta_tags.txt" >/dev/null 2>&1 && echo "cms=>joomla"
    grep -E 'React|Angular|Vue' "$dstdir/assets_js.txt" >/dev/null 2>&1 && echo "js-framework=>detected"
  } > "$tech" || echo "No tech hints detected" > "$tech"
}

dns_inventory() {
  local domain="$1"; local dstdir="$2"
  mkdir -p "$dstdir"
  if ! command -v dig >/dev/null 2>&1; then
    warn "$domain: dig missing; skipping DNS"
    echo "dig not installed" > "$dstdir/dns.txt"
    return
  fi
  log "$domain: Collecting DNS records"
  {
    echo "# A"
    dig +short A "$domain" || echo "No A records"
    echo -e "\n# AAAA"
    dig +short AAAA "$domain" || echo "No AAAA records"
    echo -e "\n# CNAME"
    dig +short CNAME "$domain" || echo "No CNAME records"
    echo -e "\n# MX"
    dig +short MX "$domain" || echo "No MX records"
    echo -e "\n# NS"
    dig +short NS "$domain" || echo "No NS records"
    echo -e "\n# TXT"
    dig +short TXT "$domain" || echo "No TXT records"
  } > "$dstdir/dns.txt" 2>/dev/null
}

whatweb_wappalyzer() {
  local domain="$1"; local dstdir="$2"
  mkdir -p "$dstdir"
  if command -v whatweb >/dev/null 2>&1; then
    log "$domain: Running WhatWeb"
    whatweb -a 1 --log-brief="$dstdir/whatweb.txt" "$(http_url_guess "$domain")" >/dev/null 2>&1 || echo "WhatWeb failed" > "$dstdir/whatweb.txt"
  else
    warn "$domain: whatweb missing"
    echo "whatweb not installed" > "$dstdir/whatweb.txt"
  fi
  if command -v wappalyzer >/dev/null 2>&1; then
    log "$domain: Running Wappalyzer"
    wappalyzer "$(http_url_guess "$domain")" > "$dstdir/wappalyzer.json" 2>/dev/null || echo "Wappalyzer failed" > "$dstdir/wappalyzer.json"
  else
    warn "$domain: wappalyzer missing"
    echo "wappalyzer not installed" > "$dstdir/wappalyzer.json"
  fi
}

subdomain_passive() {
  local domain="$1"; local dstdir="$2"
  mkdir -p "$dstdir"
  if command -v subfinder >/dev/null 2>&1; then
    log "$domain: Running Subfinder for passive subdomain enumeration"
    subfinder -silent -all -d "$domain" -o "$dstdir/subdomains.txt" 2>/dev/null || echo "Subfinder failed (check API keys or connectivity)" > "$dstdir/subdomains.txt"
  else
    warn "$domain: subfinder missing"
    echo "subfinder not installed" > "$dstdir/subdomains.txt"
  fi
}

nmap_scan() {
  local domain="$1"; local dstdir="$2"
  mkdir -p "$dstdir"
  if ! $ACTIVE; then
    log "$domain: Nmap skipped (no --active)"
    echo "Nmap not enabled" > "$dstdir/nmap.txt"
    return
  fi
  if ! command -v nmap >/dev/null 2>&1; then
    warn "$domain: nmap missing"
    echo "nmap not installed" > "$dstdir/nmap.txt"
    return
  fi
  log "$domain: Running Nmap"
  local portarg="--top-ports ${NMAP_TOP_PORTS}"
  $FULL_PORTS && portarg="-p-"
  nmap -Pn -sV -T3 --version-light ${portarg} "$domain" -oN "$dstdir/nmap.txt" -oX "$dstdir/nmap.xml" 2>/dev/null || echo "Nmap failed" > "$dstdir/nmap.txt"
}

nikto_scan() {
  local domain="$1"; local dstdir="$2"
  mkdir -p "$dstdir"
  if ! $WITH_NIKTO; then
    log "$domain: Nikto skipped (no --with-nikto)"
    echo "Nikto not enabled" > "$dstdir/nikto.txt"
    return
  fi
  if ! command -v nikto >/dev/null 2>&1; then
    warn "$domain: nikto missing"
    echo "nikto not installed" > "$dstdir/nikto.txt"
    return
  fi
  local url=$(http_url_guess "$domain")
  log "$domain: Running Nikto on $url"
  nikto -host "$url" -maxtime 900 -Tuning 123b -output "$dstdir/nikto.txt" 2>/dev/null || echo "Nikto failed" > "$dstdir/nikto.txt"
}

nuclei_scan() {
  local domain="$1"; local dstdir="$2"
  mkdir -p "$dstdir"
  if ! $WITH_NUCLEI; then
    log "$domain: Nuclei skipped (no --with-nuclei)"
    echo "Nuclei not enabled" > "$dstdir/nuclei.txt"
    return
  fi
  if ! command -v nuclei >/dev/null 2>&1; then
    warn "$domain: nuclei missing"
    echo "nuclei not installed" > "$dstdir/nuclei.txt"
    return
  fi
  local url=$(http_url_guess "$domain")
  log "$domain: Running Nuclei on $url"
  printf "%s\n" "$url" | nuclei -rate-limit "$RATE_LIMIT_NUCLEI" -timeout 10 -no-interact -silent -severity medium,high,critical -c "$RATE_LIMIT_NUCLEI" -o "$dstdir/nuclei.txt" 2>/dev/null || echo "Nuclei failed (check templates)" > "$dstdir/nuclei.txt"
}

build_findings() {
  local domain="$1"; local dstdir="$2"
  mkdir -p "$dstdir"
  local csv="$dstdir/findings.csv"
  log "$domain: Building findings CSV"
  echo "category,signal,value,notes" > "$csv"
  if [[ -s "$dstdir/http_headers.txt" ]]; then
    local server=$(awk -F": " '/^Server:/ {print $2}' "$dstdir/http_headers.txt" | tr -d '\r' || echo "none")
    [[ "$server" != "none" ]] && echo "http,server,$server,Check vendor advisories for CVEs" >> "$csv"
    local xpb=$(awk -F": " '/^X-Powered-By:/ {print $2}' "$dstdir/http_headers.txt" | tr -d '\r' || echo "none")
    [[ "$xpb" != "none" ]] && echo "http,x-powered-by,$xpb,Potential version disclosure" >> "$csv"
  else
    echo "http,headers,none,Fetch failed or no headers" >> "$csv"
  fi
  if [[ -s "$dstdir/tech_hints.txt" ]]; then
    while IFS= read -r line; do
      [[ -n "$line" ]] && echo "tech,hint,$line,Verify for outdated software" >> "$csv"
    done < "$dstdir/tech_hints.txt" || echo "tech,hints,none,No tech detected" >> "$csv"
  fi
  if [[ -s "$dstdir/whatweb.txt" ]]; then
    echo "tech,whatweb,$(tr '\n' ';' < "$dstdir/whatweb.txt" | sed 's/;/ | /g'),Check for known vulnerabilities" >> "$csv"
  else
    echo "tech,whatweb,none,No results or failed" >> "$csv"
  fi
  if [[ -s "$dstdir/wappalyzer.json" && $(command -v jq >/dev/null 2>&1 && echo "jq") ]]; then
    jq -r '.technologies[] | [.name,(.version//"unknown")] | @csv' "$dstdir/wappalyzer.json" 2>/dev/null | sed 's/^/tech,wappalyzer,/' >> "$csv" || echo "tech,wappalyzer,none,Failed to parse" >> "$csv"
  else
    echo "tech,wappalyzer,none,No results or jq missing" >> "$csv"
  fi
  if [[ -s "$dstdir/subdomains.txt" ]]; then
    while IFS= read -r sub; do
      [[ -n "$sub" ]] && echo "subdomain,found,$sub,Test for subdomain takeover" >> "$csv"
    done < "$dstdir/subdomains.txt" || echo "subdomain,found,none,No subdomains detected" >> "$csv"
  fi
  if [[ -s "$dstdir/nmap.txt" ]]; then
    awk '/open/ {print $0}' "$dstdir/nmap.txt" | while read -r line; do
      echo "service,nmap,$line,Check service versions for CVEs" >> "$csv"
    done || echo "service,nmap,none,No open ports" >> "$csv"
  fi
  [[ -s "$dstdir/nikto.txt" ]] && echo "web,nikto,see nikto.txt,Review for misconfigurations" >> "$csv"
  [[ -s "$dstdir/nuclei.txt" ]] && echo "web,nuclei,see nuclei.txt,Review for CVEs" >> "$csv"
}

html_report() {
  local domain="$1"; local dstdir="$2"
  local html="$dstdir/report.html"
  log "$domain: Generating HTML report"
  cat > "$html" <<HTML
<!doctype html>
<html lang="en"><meta charset="utf-8"><title>Recon Report — ${domain}</title>
<style>
body { font-family: system-ui, sans-serif; margin: 24px; }
pre { background: #f6f8fa; padding: 8px; border-radius: 8px; white-space: pre-wrap; }
section { margin-bottom: 24px; }
h1 { margin: 0 0 8px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 6px; text-align: left; }
th { background: #fafafa; }
small { color: #666; }
</style>
<h1>Recon Report for ${domain}</h1>
<p><strong>Domain:</strong> ${domain}<br><strong>Generated:</strong> $(date '+%F %T')</p>
<section>
<h2>HTTP Headers</h2>
<pre>$(cat "$dstdir/http_headers.txt" 2>/dev/null || echo "No headers")</pre>
</section>
<section>
<h2>Meta Tags</h2>
<pre>$(cat "$dstdir/meta_tags.txt" 2>/dev/null || echo "No meta tags")</pre>
</section>
<section>
<h2>Tech Hints</h2>
<pre>$(cat "$dstdir/tech_hints.txt" 2>/dev/null || echo "No tech hints")</pre>
</section>
<section>
<h2>DNS Records</h2>
<pre>$(cat "$dstdir/dns.txt" 2>/dev/null || echo "No DNS records")</pre>
</section>
<section>
<h2>Subdomains</h2>
<pre>$(cat "$dstdir/subdomains.txt" 2>/dev/null || echo "No subdomains")</pre>
</section>
<section>
<h2>Nmap Results</h2>
<pre>$(cat "$dstdir/nmap.txt" 2>/dev/null || echo "Nmap not run")</pre>
</section>
<section>
<h2>Findings (CSV)</h2>
<pre>$(head -n 200 "$dstdir/findings.csv" 2>/dev/null || echo "No findings")</pre>
</section>
<p><small>Informational only. Validate findings and check CVEs. Run only on in-scope targets. © $(date '+%Y')</small></p>
</html>
HTML
}

list_output() {
  local dstdir="$1"
  log "Files generated in $dstdir:"
  ls -l "$dstdir" 2>/dev/null || log "No files generated"
}

process_domain() {
  local raw="$1"
  local domain=$(normalize_domain "$raw")
  local dstdir="$OUTDIR/$domain"
  mkdir -p "$dstdir"
  log "===== Processing $domain ====="
  if ! validate_target "$domain"; then
    warn "$domain: Skipping due to DNS failure"
    echo "Domain failed validation" > "$dstdir/error.txt"
    list_output "$dstdir"
    return
  fi
  fingerprint_http "$domain" "$dstdir"
  dns_inventory "$domain" "$dstdir"
  whatweb_wappalyzer "$domain" "$dstdir"
  subdomain_passive "$domain" "$dstdir"
  nmap_scan "$domain" "$dstdir"
  nikto_scan "$domain" "$dstdir"
  nuclei_scan "$domain" "$dstdir"
  build_findings "$domain" "$dstdir"
  html_report "$domain" "$dstdir"
  list_output "$dstdir"
  log "===== Done: $domain ====="
}

main() {
  log "Starting $SCRIPT_NAME v$VERSION"
  parse_args "$@"
  mkoutdir
  check_dependencies
  log "Configuration: Active=$ACTIVE, FullPorts=$FULL_PORTS, Nikto=$WITH_NIKTO, Nuclei=$WITH_NUCLEI, Output=$OUTDIR"
  for t in "${TARGETS[@]}"; do
    process_domain "$t"
    [[ "$DELAY" -gt 0 ]] && { log "Pausing for $DELAY seconds"; sleep "$DELAY"; }
  done
  log "Completed. Results in: $OUTDIR"
  list_output "$OUTDIR"
}

main "$@"
