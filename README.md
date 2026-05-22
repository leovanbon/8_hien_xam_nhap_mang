# Simple Network Intrusion Detection System

This repository is an intro cybersecurity class project. It demonstrates how a
Network Intrusion Detection System (NIDS) can capture packets, parse useful
fields, apply basic detection rules, and print or save alerts.

The project is intentionally small and rule based. It is meant for learning,
not for production monitoring.

## Features

- Live packet capture with Scapy
- Packet parsing for IP, TCP, UDP, ICMP, ports, TCP flags, and payload text
- ICMP flood detection
- Basic TCP port scan detection
- Signature detection for SQL injection, XSS, and path traversal payloads
- Console alerts and optional JSON Lines alert logs
- Safe localhost demo traffic scripts
- Unit tests for the detection rules

## Project Layout

```text
.
├── main.py              # CLI entry point for the NIDS
├── demo_http_server.py  # Local HTTP server for payload demos
├── demo_traffic.py      # Safe localhost demo traffic generator
├── requirement.txt      # Python dependency list
├── src/
│   ├── alert.py         # Alert model and logger
│   ├── detector.py      # Rule-based detection logic
│   ├── parser.py        # Scapy packet parser
│   └── sniffer.py       # Scapy packet capture wrapper
└── tests/
    └── test_detector.py
```

## Install

Use a virtual environment if possible:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirement.txt
```

## Run the NIDS

Packet sniffing usually requires administrator privileges.

On Linux, this listens on Scapy's default interface:

```bash
sudo python main.py
```

To sniff only localhost HTTP traffic:

```bash
sudo python main.py --interface lo --filter "tcp port 8080" --log alerts.jsonl
```

Useful options:

```bash
python main.py --help
```

## Safe Class Demo

Use terminal 1 to start the local demo server:

```bash
python demo_http_server.py
```

Use terminal 2 to start the NIDS. This broader TCP filter catches both the
payload demos and the multi-port scan demo:

```bash
sudo python main.py --interface lo --filter "tcp" --log alerts.jsonl
```

Use terminal 3 to send demo traffic:

```bash
python demo_traffic.py sqli
python demo_traffic.py xss
python demo_traffic.py path
python demo_traffic.py port-scan --port 9000 --count 12
```

If you only want to demonstrate SQL injection, XSS, and path traversal payload
alerts, you can narrow the NIDS filter to `tcp port 8080`.

For the port scan demo, keep the NIDS filter broad enough to see multiple
destination ports. Use `--filter "tcp"`, not `--filter "tcp port 8080"`.

Only run the demo traffic against localhost or systems you own and are allowed
to test.

## Detection Logic

ICMP flood:

- Tracks ICMP packets per source IP.
- Alerts when the count passes a threshold inside a time window.

Port scan:

- Tracks distinct TCP destination ports per source IP.
- Alerts when one source touches many ports inside a time window.

Payload signatures:

- Converts packet payloads to lowercase text.
- Looks for simple suspicious strings such as `union select`, `<script>`,
  `/etc/passwd`, and path traversal patterns.

## Run Tests

```bash
python -m unittest discover
```

## Limitations

- Encrypted traffic such as HTTPS cannot be inspected for payload signatures.
- The signatures are simple strings, so they can miss obfuscated attacks.
- The port scan and flood rules can produce false positives.
- This project does not block traffic; it only observes and alerts.
