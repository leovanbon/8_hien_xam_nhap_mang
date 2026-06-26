# Tổng quan

Hệ thống NIDS nhỏ gọn viết bằng Python, phục vụ mục đích **học tập và trình diễn** các thành phần cốt lõi của một pipeline phát hiện xâm nhập mạng:

1. **Thu thập gói tin** — đọc PCAP hoặc sniff live interface bằng Scapy.
2. **Chuẩn hóa** — chuyển gói tin thô thành đối tượng `PacketEvent` (IP, port, TCP flags, DNS query, HTTP fields…).
3. **Phát hiện hành vi** — cửa sổ trượt thời gian cho port scan, ICMP flood, SYN flood, DNS tunneling.
4. **Phát hiện chữ ký** — engine phân tích cú pháp Suricata-style subset (content, pcre, sticky buffers…).
5. **Lưu trữ** — ghi cảnh báo ra JSON Lines (`data/alerts.jsonl`).
6. **Dashboard** — Flask web UI hiển thị thống kê cảnh báo realtime.

```
┌──────────┐     ┌───────────┐     ┌───────────────────┐     ┌─────────┐     ┌───────────┐
│ Capture  │───▶│  Parser   │───▶│ Detection Engine  │───▶│ Storage │───▶│ Dashboard │
│ (Scapy)  │     │PacketEvent│     │Behavior+Signature │     │ (JSONL) │     │  (Flask)  │
└──────────┘     └───────────┘     └───────────────────┘     └─────────┘     └───────────┘
```

---

# Cấu trúc thư mục

```
.
├── main.py                   # CLI entry point (--pcap / --iface)
├── custom.rules              # Luật chữ ký Suricata-style cho demo
├── requirements.txt
├── pyproject.toml
│
├── nids/                     # Core NIDS engine
│   ├── capture.py            #   PCAP reader & live sniffer
│   ├── parser.py             #   Scapy → PacketEvent normalization
│   ├── engine.py             #   Orchestration & packet counters
│   ├── models.py             #   PacketEvent & Alert dataclasses
│   ├── http_utils.py         #   HTTP request-line & header parser
│   ├── storage.py            #   JSONL alert writer
│   └── rules/                #   Detection rule engine
│       ├── behavior.py       #     Sliding-window behavior rules
│       ├── engine.py         #     Suricata-style signature matcher
│       ├── parser.py         #     Rule text → SuricataRule parser
│       ├── models.py         #     SuricataRule & ContentMatch models
│       ├── buffers.py        #     Sticky buffer resolver
│       └── config.py         #     RuleConfig defaults
│
├── dashboard/
│   ├── app.py                # Flask web application
│   ├── static/style.css
│   └── templates/index.html
│
├── scripts/
│   ├── kali_attacks.sh       # Kịch bản 10 bài tấn công từ Kali
│   └── demo_events.py        # Sinh cảnh báo giả lập (không cần mạng)
│
├── tests/
│   └── test_rules.py         # Unit tests cho detection logic
│
├── report/                   # Báo cáo LaTeX (PDF: report/report.pdf)
│   ├── main.tex
│   ├── chapters/chap{1..5}.tex
│   └── ...
│
└── pres/                     # Slide trình bày Beamer
    ├── Slide_HUST.tex
    └── Slide_HUST.pdf
```

---

# Cài đặt

```bash
# Clone & setup
git clone <repo-url> && cd 8_hien_xam_nhap_mang
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Yêu cầu:** Python ≥ 3.10, `scapy` ≥ 2.5, `Flask` ≥ 3.0.  
Live capture cần quyền root / sudo.

---

# Sử dụng

## Phân tích file PCAP

```bash
python3 main.py --pcap sample.pcap
python3 main.py --pcap sample.pcap --alerts data/lab-run.jsonl   # custom output
```

## Live capture

```bash
sudo .venv/bin/python main.py --iface virbr0 --rules custom.rules --limit 0
```

- `--iface` — network interface để sniff.
- `--rules` — file luật chữ ký Suricata-style (nạp song song với luật hành vi mặc định).
- `--limit 0` — sniff vô hạn (Ctrl+C để dừng).

## Demo nhanh

```bash
python3 scripts/demo_events.py      # sinh alerts giả lập
python3 dashboard/app.py            # mở dashboard tại http://127.0.0.1:5000
```

### Chạy tests

```bash
python3 -m unittest discover -s tests
```

---

# Luật phát hiện

## Hành vi (Behavior-based) — mặc định, luôn bật

| Rule ID | Tấn công | Ngưỡng mặc định | Severity |
|---|---|---|---|
| `RULE-001` | Port Scan | ≥ 20 TCP dest ports / 10 s từ 1 source | Medium |
| `RULE-002` | ICMP Ping Flood | ≥ 100 ICMP request / 10 s | High |
| `RULE-003` | TCP SYN Flood | ≥ 100 SYN (no ACK) / 10 s → 1 service | High |
| `RULE-004` | DNS Tunneling | ≥ 5 suspicious queries / 30 s | Medium |

DNS Tunneling dùng 3 chỉ số bất thường: tổng query ≥ 100 ký tự, label ≥ 45 chars, hoặc Shannon entropy ≥ 3.8 (với label ≥ 24 chars).

## Chữ ký (Signature-based) — nạp từ file `.rules`

File [`custom.rules`](custom.rules) chứa 6 luật demo:

| SID | Tấn công | Sticky Buffer |
|---|---|---|
| `1000101` | Custom DNS query (`example.com`) | `dns.query` |
| `1000001` | SQL Injection GET | `http.uri` |
| `1000002` | sqlmap User-Agent | `http.user_agent` |
| `1000003` | SQL Injection POST | `pkt_data` |
| `900004` | Brute Force (detection_filter) | `content` |
| `1000005` | .env file access | `http.uri` |

**Suricata-style subset hỗ trợ:**
- Header: `alert`, protocols (`tcp`/`udp`/`icmp`/`dns`/`http`…), IP/port/CIDR, direction (`->`, `<>`)
- Options: `msg`, `sid`, `rev`, `classtype`, `priority`, `flow`, `content`, `pcre`, `nocase`, `fast_pattern`, `threshold`, `detection_filter`
- Sticky buffers: `pkt_data`, `raw_data`, `dns.query`, `http.method`, `http.uri`, `http.request_line`, `http.header`, `http.host`, `http.user_agent`

---

# Thực nghiệm (Lab Demo)

## Mô hình mạng

```
┌────────────────────┐         traffic          ┌─────────────────┐
│  Kali Linux (ATK)  │◄───────────────────────▶│  Win10 (Victim)  │
│  192.168.122.230   │                          │  192.168.122.54  │
└────────────────────┘                          └─────────────────┘
            │  sniff (promiscuous)
            ▼
   ┌─────────────────────────┐
   │  Host (NIDS + Dashboard) │
   │  192.168.122.1 / virbr0  │
   └─────────────────────────┘
```

**Nền tảng ảo hóa:** KVM/QEMU (libvirt), mạng NAT `virbr0` subnet `192.168.122.0/24`.

## Các bước chạy demo

**1. Host — Khởi động Dashboard:**
```bash
source .venv/bin/activate
python3 dashboard/app.py
# → http://127.0.0.1:5000
```

**2. Host — Khởi động NIDS Engine:**
```bash
sudo .venv/bin/python main.py --iface virbr0 --rules custom.rules --limit 0
```

**3. Kali — Chạy kịch bản tấn công:**
```bash
chmod +x kali_attacks.sh
sudo ./kali_attacks.sh
```

Script [`kali_attacks.sh`](scripts/kali_attacks.sh) chạy **10 kịch bản** tấn công:

| # | Kịch bản | Luật | Công cụ |
|---|---|---|---|
| 1 | Nmap Port Scan | RULE-001 | `nmap -sS` |
| 2 | ICMP Ping Flood | RULE-002 | `hping3 --icmp` |
| 3 | TCP SYN Flood | RULE-003 | `hping3 -S` |
| 4 | DNS Tunneling | RULE-004 | `dig` (high-entropy labels) |
| 5 | Custom DNS Signature | SID 1000101 | `dig example.com` |
| 6 | sqlmap User-Agent | SID 1000002 | `curl -A` |
| 7 | SQL Injection GET | SID 1000001 | `curl` (URL-encoded) |
| 8 | SQL Injection POST | SID 1000003 | `curl -X POST` |
| 9 | Brute Force | SID 900004 | `curl` loop ×10 |
| 10 | .env File Access | SID 1000005 | `curl /.env` |

## Kết quả thực nghiệm

Tất cả 10 kịch bản kích hoạt cảnh báo đúng (True Positive 100% trong môi trường lab). Chi tiết xem [báo cáo chương 4](report/chapters/chap4.tex).

---

# Định dạng cảnh báo (JSONL)

```json
{
  "timestamp": "2026-06-25T06:57:04+00:00",
  "rule_id": "RULE-001",
  "attack_type": "Port Scan",
  "detection_method": "behavior",
  "severity": "Medium",
  "source_ip": "192.168.122.230",
  "destination_ip": "192.168.122.54",
  "description": "192.168.122.230 contacted 20 unique TCP ports in 10 seconds",
  "evidence": {
    "count": 20,
    "unique_ports": [21, 22, 23, 25, 53, 80, ...]
  }
}
```

Priority → Severity: `1` = High, `2` = Medium, `3` = Low, khác = Informational.

---

# Hạn chế

- Không defrag IP, không reassemble TCP stream → payload chia nhỏ có thể bị bỏ sót.
- Không giải mã TLS/HTTPS/DoH/DoT → chữ ký chỉ hoạt động trên plaintext.
- Scapy + single-thread Python → không phù hợp mạng tốc độ cao.
- Ngưỡng hành vi là giá trị lab/demo, cần tune theo baseline thực tế.
- `flow` chỉ kiểm tra hướng cơ bản, chưa stateful TCP tracking.

---

# Tài liệu

| Tài liệu | Vị trí |
|---|---|
| Báo cáo đầy đủ (PDF) | [`report/report.pdf`](report/report.pdf) |
| Slide trình bày (PDF) | [`pres/Slide_HUST.pdf`](pres/Slide_HUST.pdf) |
| Chi tiết Rule Engine | [`nids/README.md`](nids/README.md) |
| Chi tiết Dashboard | [`dashboard/README.md`](dashboard/README.md) |

---

