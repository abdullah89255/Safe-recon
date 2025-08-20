#!/bin/bash

# ┌──────────────────────────────┐
# │     Web Vuln Scanner v1.0    │
# └──────────────────────────────┘
# Usage: ./web_vuln_scan.sh https://target.com

target=$1

if [ -z "$target" ]; then
    echo "Usage: $0 https://target.com"
    exit 1
fi

echo "[*] Target: $target"
domain=$(echo $target | awk -F/ '{print $3}')
mkdir -p "$domain-scan"
cd "$domain-scan" || exit

# -------------------- Step 1: Detect Tech Stack --------------------
echo "[*] Running httpx for technology and server detection..."
echo $target | httpx -title -tech-detect -status-code -web-server -tls-probe -silent > httpx-info.txt

echo "[*] Running WhatWeb..."
whatweb $target > whatweb.txt

echo "[*] Running wafw00f for WAF detection..."
wafw00f $target > waf.txt

echo "[*] Nuclei - Technology templates"
nuclei -u $target -t technologies/ > nuclei_tech.txt

# -------------------- Step 2: URL & Param Discovery --------------------
echo "[*] Discovering URLs using waybackurls..."
echo $target | waybackurls | uro | tee wayback.txt

echo "[*] Running gf for param-based endpoints..."
gf xss wayback.txt > xss.txt
gf sqli wayback.txt > sqli.txt
gf lfi wayback.txt > lfi.txt
gf ssti wayback.txt > ssti.txt
gf xxe wayback.txt > xxe.txt
gf idor wayback.txt > idor.txt

# -------------------- Step 3: Vuln Scanning --------------------
echo "[*]  scan with nuclei (quick check)..."
cat xss.txt | nuclei -tags xss | tee reasultsXSS.txt
cat sqli.txt | nuclei -tags sqli | tee reasultsSQLI.txt
cat lfi.txt | nuclei -tags lfi | tee reasultsLFI.txt
cat ssti.txt | nuclei -tags ssti | tee reasultsSSTi.txt
cat idor.txt | nuclei -tags idor | tee reasultsIDOR.txt
cat xxe.txt | nuclei -tags xxe | tee reasultsXXE.txt

echo "[*] SQLi scan with sqlmap (quick check)..."
head -n 5 sqli.txt | while read url; do
    echo "[*] Testing $url"
    sqlmap -u "$url" --batch --level=1 --risk=1 --crawl=0 --threads=1 --timeout=10 --random-agent --technique=BEUSTQ >> sqlmap_result.txt
done

echo "[*] LFI test with FFUF (basic)..."
ffuf -w /usr/share/wordlists/lfi-common.txt -u "$target?file=FUZZ" -mc 200,500 -of csv -o ffuf_lfi.csv

# -------------------- Step 4: Output Summary --------------------
echo ""
echo "✔ Scan Complete for $target"
echo "Results saved in: $(pwd)"

tree . | tee scan_summary.txt
