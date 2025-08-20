#!/usr/bin/env bash
# =============================================================
# frontend-recon.sh — Safe, non-invasive recon for SPAs (React/Angular/Vue)
# Collects JS, extracts endpoints/routes, scans for secrets, checks CORS headers,
# and fingerprints frameworks. Generates a tidy /out folder and a human report.
#
# IMPORTANT: Use only on assets you own or have written permission to test.
# This script avoids active exploitation. It does NOT fuzz/attack.
# =============================================================

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <domain> [--deep] [--generate-poc]"
  echo "  --deep          : also crawl live site with katana (if installed)"
  echo "  --generate-poc  : create example (commented) curl payload templates for manual XSS/IDOR testing"
  exit 1
fi

DOMAIN="$1"
shift || true
DEEP=false
GEN_POC=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --deep) DEEP=true; shift ;;
    --generate-poc) GEN_POC=true; shift ;;
    *) echo "[!] Unknown option: $1"; exit 1 ;;
  esac
done

STAMP=$(date +%Y%m%d-%H%M%S)
ROOT="out/${DOMAIN}-${STAMP}"
mkdir -p "$ROOT"/{fingerprint,js,api,secrets,scan,reports,poc}

log() { printf "[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }

# -------------------------------------------------------------
# 0) Basic target normalization
# -------------------------------------------------------------
BASE="https://${DOMAIN}"
log "Target: $BASE"
log "Output: $ROOT"

# -------------------------------------------------------------
# 1) Fingerprint framework (React/Angular/Vue)
# -------------------------------------------------------------
log "Fingerprinting framework…"
{
  curl -sSL --max-time 20 "$BASE" | tee "$ROOT/fingerprint/index.html" >/dev/null
} || true

INDEX="$ROOT/fingerprint/index.html"

FRAMEWORKS=()
if grep -q "__REACT_DEVTOOLS_GLOBAL_HOOK__" "$INDEX" || grep -qiE 'react|react-dom' "$INDEX"; then
  FRAMEWORKS+=("React")
fi
if grep -qiE 'ng-version|angular[[:space:]]*\.?(?:js|min\.js)?' "$INDEX" || grep -q "__ngDevMode" "$INDEX"; then
  FRAMEWORKS+=("Angular")
fi
if grep -q "__VUE_DEVTOOLS_GLOBAL_HOOK__" "$INDEX" || grep -qiE '(vue\.js|vue\.min\.js)' "$INDEX"; then
  FRAMEWORKS+=("Vue")
fi

printf "%s\n" "${FRAMEWORKS[@]:-Unknown}" > "$ROOT/fingerprint/frameworks.txt"
log "Detected: $(tr '\n' ' ' < "$ROOT/fingerprint/frameworks.txt" | sed 's/ $//')"

# Look for typical bundle names
log "Hunting for SPA bundles…"
awk 'match($0, /src=\"([^\"]+\.(js|mjs))(\?[^\"]*)?\"/, a){print a[1]}' "$INDEX" | sed 's/^\///' | sort -u > "$ROOT/js/bundles.txt" || true

# -------------------------------------------------------------
# 2) Collect JS URLs (archived + discovered)
# -------------------------------------------------------------
log "Collecting JS URLs from Wayback…"
if command -v waybackurls >/dev/null 2>&1; then
  waybackurls "$DOMAIN" | grep -Ei '\\.m?js(\\?.*)?$' | sort -u > "$ROOT/js/js-urls.txt" || true
else
  log "waybackurls not found — skipping archive collection"
  : > "$ROOT/js/js-urls.txt"
fi

# Merge with on-page bundles
if [[ -s "$ROOT/js/bundles.txt" ]]; then
  while read -r rel; do
    [[ -z "$rel" ]] && continue
    if [[ "$rel" =~ ^https?:// ]]; then echo "$rel"; else echo "$BASE/${rel#./}"; fi
  done < "$ROOT/js/bundles.txt" | sort -u >> "$ROOT/js/js-urls.txt"
fi
sort -u -o "$ROOT/js/js-urls.txt" "$ROOT/js/js-urls.txt"
log "JS URLs collected: $(wc -l < "$ROOT/js/js-urls.txt")"

# Optional live crawl (safe)
if $DEEP && command -v katana >/dev/null 2>&1; then
  log "Deep crawling with katana…"
  katana -u "$BASE" -jc -xhr -kf | grep -Ei '\\.m?js(\\?.*)?$' | sort -u >> "$ROOT/js/js-urls.txt" || true
  sort -u -o "$ROOT/js/js-urls.txt" "$ROOT/js/js-urls.txt"
  log "JS URLs after deep crawl: $(wc -l < "$ROOT/js/js-urls.txt")"
fi

# -------------------------------------------------------------
# 3) Download JS for local analysis
# -------------------------------------------------------------
log "Downloading JS files…"
while read -r url; do
  [[ -z "$url" ]] && continue
  name=$(echo "$url" | sed 's#[^a-zA-Z0-9._-]#_#g')
  curl -sSL --max-time 25 "$url" -o "$ROOT/js/$name" || true
done < "$ROOT/js/js-urls.txt"

# -------------------------------------------------------------
# 4) Extract endpoints, routes, and candidates
# -------------------------------------------------------------
log "Extracting endpoints from JS…"
grep -Eho "https?://[a-zA-Z0-9._:-]+(/[a-zA-Z0-9._:/?&%+-]*)?" "$ROOT/js"/* 2>/dev/null | sort -u > "$ROOT/api/endpoints-all.txt" || true

# Deduplicate to own domain and likely APIs
awk -v d="$DOMAIN" 'BEGIN{IGNORECASE=1}
{
  if ($0 ~ d || $0 ~ /api\b|graphql|v[0-9]+\//) print $0
}' "$ROOT/api/endpoints-all.txt" | sort -u > "$ROOT/api/endpoints.txt"
log "Endpoints found: $(wc -l < "$ROOT/api/endpoints.txt") (likely) / $(wc -l < "$ROOT/api/endpoints-all.txt") (all)"

# Extract route-like paths (for SPA routers)
log "Extracting client routes…"
grep -Eho "\"\/[a-zA-Z0-9_\-\/]{2,}\"" "$ROOT/js"/* 2>/dev/null | tr -d '"' | sort -u > "$ROOT/api/client-routes.txt" || true

# -------------------------------------------------------------
# 5) Secrets scanning (JS)
# -------------------------------------------------------------
log "Scanning for secrets (grep patterns)…"
: > "$ROOT/secrets/grep-secrets.txt"
grep -RinoE "(api[_-]?key|secret|token|bearer|auth|firebase|stripe|aws|access[_-]?key|client[_-]?secret|password)" "$ROOT/js"/* 2>/dev/null | tee -a "$ROOT/secrets/grep-secrets.txt" || true

if command -v python3 >/dev/null 2>&1 && [[ -f SecretFinder.py ]]; then
  log "Running SecretFinder.py (if rules present)…"
  python3 SecretFinder.py -i "$ROOT/js/" -o cli | tee "$ROOT/secrets/secretfinder.txt" || true
else
  log "SecretFinder.py not found next to script — skipping (optional)."
fi

# Check for exposed source maps
log "Checking for exposed source maps…"
: > "$ROOT/secrets/source-maps.txt"
while read -r jurl; do
  [[ -z "$jurl" ]] && continue
  map="$jurl.map"
  code=$(curl -s -o /dev/null -w "%{http_code}" "$map" || true)
  if [[ "$code" == "200" ]]; then
    echo "$map" | tee -a "$ROOT/secrets/source-maps.txt"
  fi
done < "$ROOT/js/js-urls.txt"

# -------------------------------------------------------------
# 6) Header sanity & CORS check (safe)
# -------------------------------------------------------------
log "Checking CORS headers on likely endpoints…"
: > "$ROOT/scan/cors.txt"
while read -r api; do
  [[ -z "$api" ]] && continue
  headers=$(curl -sI --max-time 15 -H "Origin: https://example.com" "$api" || true)
  if echo "$headers" | grep -qi "Access-Control-Allow-Origin"; then
    printf "[CORS header present] %s\n" "$api" | tee -a "$ROOT/scan/cors.txt"
  fi
  # record security headers snapshot
  printf "\n# %s\n%s\n" "$api" "$headers" >> "$ROOT/scan/security-headers.txt"
done < "$ROOT/api/endpoints.txt"

# -------------------------------------------------------------
# 7) Optional: generate commented PoC templates (NOT executed)
# -------------------------------------------------------------
if $GEN_POC; then
  log "Generating commented PoC templates (manual use only)…"
  POC="$ROOT/poc/examples.sh"
  {
    echo "#!/usr/bin/env bash"
    echo "# PoC templates for manual testing on authorized targets only."
    echo "# These are COMMENTED OUT on purpose to prevent accidental execution."
    echo "# Remove leading '#' ONLY if you have explicit permission."
    echo
    echo "# --- XSS reflection probe (GET) example:"
    echo "# curl -sS \"https://${DOMAIN}/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E\""
    echo
    echo "# --- XSS reflection probe (JSON field) example:"
    echo "# curl -sS -X POST \"https://${DOMAIN}/api/example\" -H 'Content-Type: application/json' \
#   --data '{\"comment\":\"<svg onload=alert(1)>\"}'"
    echo
    echo "# --- IDOR manual diff template:"
    echo "# for id in 100 101 102; do"
    echo "#   curl -sS \"https://${DOMAIN}/api/users/\${id}\" -H 'Authorization: Bearer REPLACE_ME' | jq ."
    echo "# done"
  } > "$POC"
  chmod +x "$POC"
fi

# -------------------------------------------------------------
# 8) Human-readable report
# -------------------------------------------------------------
REPORT="$ROOT/reports/summary.md"
log "Writing summary report…"
{
  echo "# SPA Recon Summary for $DOMAIN ($STAMP)"
  echo
  echo "## Frameworks Detected"
  if [[ -s "$ROOT/fingerprint/frameworks.txt" ]]; then
    cat "$ROOT/fingerprint/frameworks.txt" | sed 's/^/- /'
  else
    echo "- Unknown"
  fi
  echo
  echo "## Key Files"
  echo "- JS URLs: $(wc -l < "$ROOT/js/js-urls.txt")"
  echo "- Likely endpoints: $(wc -l < "$ROOT/api/endpoints.txt")"
  echo "- Client routes: $(wc -l < "$ROOT/api/client-routes.txt")"
  echo
  echo "## Notable Findings"
  echo "- CORS header present on: $(wc -l < "$ROOT/scan/cors.txt") endpoints"
  echo "- Source maps exposed: $(wc -l < "$ROOT/secrets/source-maps.txt" 2>/dev/null || echo 0)"
  echo "- Grep potential secrets hits: $(wc -l < "$ROOT/secrets/grep-secrets.txt" 2>/dev/null || echo 0) lines"
  echo
  echo "## Next Steps (Manual, Ethical Testing Only)"
  echo "1. Review endpoints for authz gaps (IDOR)."
  echo "2. Inspect source maps if present — look for hidden routes and privileged APIs."
  echo "3. Validate CORS policies against bug bounty rules."
  echo "4. Use the generated PoC templates responsibly (if --generate-poc was used)."
} > "$REPORT"

log "Done. See $REPORT"

exit 0
