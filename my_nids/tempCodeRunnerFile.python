from scapy.all import sniff, IP, TCP, ICMP
from collections import Counter
import time

# Cấu hình ngưỡng cảnh báo
PORT_SCAN_THRESHOLD = 20
ICMP_FLOOD_THRESHOLD = 10
suspicious_ips = Counter()
icmp_counter = Counter()

# Danh sách các từ khóa độc hại (Signature-based)
SIGNATURES = [
    "union select", "drop table", "alert(", "<script>", "/etc/passwd"
]

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # 1. Phát hiện ICMP Flood (Ping Flood)
        if packet.haslayer(ICMP):
            icmp_counter[src_ip] += 1
            if icmp_counter[src_ip] > ICMP_FLOOD_THRESHOLD:
                print(f"[!] CẢNH BÁO: Phát hiện ICMP Flood từ {src_ip}!")
                icmp_counter[src_ip] = 0 # Reset sau khi cảnh báo

        # 2. Phát hiện Port Scanning
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            # Theo dõi số lượng port khác nhau mà một IP thử kết nối
            suspicious_ips[src_ip] += 1
            
            if suspicious_ips[src_ip] > PORT_SCAN_THRESHOLD:
                print(f"[!] CẢNH BÁO: Phát hiện dấu hiệu Port Scanning từ {src_ip}!")
                suspicious_ips[src_ip] = 0

            # 3. Phân tích nội dung gói tin (Dấu hiệu tấn công Web/SQLi)
            try:
                payload = str(packet[TCP].payload).lower()
                for signature in SIGNATURES:
                    if signature in payload:
                        print(f"[!!!] CẢNH BÁO: Phát hiện nội dung nghi vấn '{signature}' từ {src_ip} tới {dst_ip}")
            except Exception:
                pass

def main():
    print("--- Đang khởi động NIDS Demo ---")
    print("Đang lắng nghe lưu lượng mạng... (Nhấn Ctrl+C để dừng)")
    
    # Bắt đầu bắt gói tin (sniffing)
    # filter="ip": chỉ bắt gói tin IP
    # prn: hàm sẽ thực hiện với mỗi gói tin bắt được
    sniff(filter="ip", prn=process_packet, store=False)

if __name__ == "__main__":
    main()