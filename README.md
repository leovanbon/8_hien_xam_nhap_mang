# Simple NIDS Semester Project

This is a small Network Intrusion Detection System framework written in Python.
It can read packets from a PCAP file or capture live traffic, extract packet
metadata, run simple rule-based detections, and store alerts for a Flask
dashboard.

## Features

- Packet metadata extraction with Scapy
- Rule-based detection for:
  - Port scans
  - ICMP ping floods
  - TCP SYN floods
  - Suspicious DNS queries
- JSONL alert storage
- Minimal Flask dashboard
- Unit tests for detection logic

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Analyze A PCAP

```bash
python3 main.py --pcap sample.pcap
```

## Live Capture

Live packet capture often needs administrator/root privileges.

```bash
sudo .venv/bin/python main.py --iface eth0 --limit 500
```

## Run Dashboard

```bash
python3 dashboard/app.py
```

Then open:

```text
http://127.0.0.1:5000
```

## Generate Demo Alerts

This creates sample alerts without needing a PCAP file or live capture.

```bash
python3 scripts/demo_events.py
```

## Run Tests

```bash
python3 -m unittest discover -s tests
```

## Project Layout

```text
.
├── main.py
├── requirements.txt
├── nids/
│   ├── capture.py
│   ├── engine.py
│   ├── models.py
│   ├── parser.py
│   ├── rules.py
│   └── storage.py
├── dashboard/
│   ├── app.py
│   ├── static/
│   │   └── style.css
│   └── templates/
│       └── index.html
└── tests/
    └── test_rules.py
```
