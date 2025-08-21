#!/bin/bash

# 🔍 Improved Subdomain Enumeration Script (2025 Edition)
# Usage: ./enum_subdomains.sh <domain> (e.g., example.com)
# Enhancements: More tools (Assetfinder, Sublist3r, optional BBOT), auto-download wordlist for better results.
# Outputs: ./out/<domain> with subdomains.csv, live_report.html, screenshots, raw files.

if [ $# -ne 1 ]; then
    echo "❌ Usage: $0 <domain>"
    exit 1
fi

DOMAIN=$1
OUT_DIR="./out/$DOMAIN"
WORDLIST_DIR="./wordlists"
WORDLIST="$WORDLIST_DIR/best-dns-wordlist.txt"
WORDLIST_URL="https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt"  # Top-rated for 2025

# Create directories
mkdir -p "$OUT_DIR" "$WORDLIST_DIR"
echo "📁 Created output directory: $OUT_DIR"

# Download wordlist if not present 📥
if [ ! -f "$WORDLIST" ]; then
    echo "🔽 Downloading high-quality DNS wordlist..."
    curl -sL "$WORDLIST_URL" -o "$WORDLIST" || { echo "❌ Wordlist download failed!"; exit 1; }
fi

# Optional tools (warn if missing)
SUBLIST3R_PATH="/home/kali/Desktop/Sublist3r/sublist3r.py"  # ⚠️ Replace with your path! (git clone https://github.com/aboul3la/Sublist3r && pip install -r requirements.txt)
BBOT_INSTALLED=$(command -v bbot >/dev/null 2>&1 && echo yes || echo no)

# Step 1: Passive Enumeration with Multiple Tools 🌐
echo "🔍 Running passive enumeration..."
subfinder -d "$DOMAIN" -o "$OUT_DIR/subfinder.txt" || { echo "❌ Subfinder failed!"; exit 1; }
assetfinder --subs-only "$DOMAIN" > "$OUT_DIR/assetfinder.txt" || { echo "❌ Assetfinder failed!"; exit 1; }

# Add Sublist3r if path set
if [ -f "$SUBLIST3R_PATH" ]; then
    python3 "$SUBLIST3R_PATH" -d "$DOMAIN" -o "$OUT_DIR/sublist3r.txt" || echo "⚠️ Sublist3r failed, skipping."
else
    echo "⚠️ Sublist3r path not set or missing, skipping."
fi

# Add BBOT if installed (for max subdomains)
if [ "$BBOT_INSTALLED" = "yes" ]; then
    echo "🔍 Running BBOT for advanced passive enum (more results)..."
    bbot -t "$DOMAIN" -f subdomain-enum -m all --yes --allow-deadly -o "$OUT_DIR/bbot.json" --json
    jq -r '.events[] | select(.type=="DNS_NAME" and .data | test("^.*\\.'"$DOMAIN"'$")) | .data' "$OUT_DIR/bbot.json" > "$OUT_DIR/bbot.txt"
else
    echo "⚠️ BBOT not installed (pip install bbot), skipping for now. Install for better results!"
fi

# Step 2: Active Enumeration with Amass ⚡
echo "🔍 Running active enumeration with brute-force..."
amass enum -active -d "$DOMAIN" -brute -w "$WORDLIST" -o "$OUT_DIR/amass.txt" || { echo "❌ Amass failed!"; exit 1; }

# Step 3: Combine and Unique Results ✅
echo "🧹 Combining and filtering unique subdomains..."
cat "$OUT_DIR/"*.txt | grep -E "\.${DOMAIN}$" | sort -u > "$OUT_DIR/all_subdomains.txt"

# Step 4: Verify Live Subdomains with httpx 🌟
echo "🔍 Verifying live subdomains..."
cat "$OUT_DIR/all_subdomains.txt" | httpx -silent -o "$OUT_DIR/live_subdomains.txt" || { echo "❌ httpx failed!"; exit 1; }

# Step 5: Generate Screenshots and HTML Report with Aquatone 📸
echo "📸 Generating screenshots and HTML report..."
cat "$OUT_DIR/live_subdomains.txt" | aquatone -out "$OUT_DIR/aquatone_report" || { echo "❌ Aquatone failed!"; exit 1; }
mv "$OUT_DIR/aquatone_report/aquatone_report.html" "$OUT_DIR/live_report.html"  # Rename for clarity

# Step 6: Create CSV Output 📊
echo "📄 Generating CSV..."
echo "Subdomain,Status,Source" > "$OUT_DIR/subdomains.csv"
while IFS= read -r sub; do
    echo "$sub,Live,Verified" >> "$OUT_DIR/subdomains.csv"
done < "$OUT_DIR/live_subdomains.txt"
# Add inactive ones
grep -v -f "$OUT_DIR/live_subdomains.txt" "$OUT_DIR/all_subdomains.txt" | while IFS= read -r sub; do
    echo "$sub,Inactive,Enumerated" >> "$OUT_DIR/subdomains.csv"
done

echo "✅ Enumeration complete! Check $OUT_DIR for results:"
echo "  - subdomains.csv: Full list in CSV (with status and source hints)"
echo "  - live_report.html: HTML with screenshots"
echo "  - all_subdomains.txt: All unique subdomains"
echo "  - Other .txt files: Tool-specific outputs"
echo "💡 Tip: For even more subdomains, install BBOT and rerun. If still low results, try a larger wordlist or API configs for tools."
