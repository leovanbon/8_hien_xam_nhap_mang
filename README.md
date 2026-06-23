# Simple NIDS Semester Project

This project is a small Network Intrusion Detection System written in Python.
It can read traffic from a PCAP file or a live network interface, normalize
packets into simple event objects, evaluate behavior/anomaly rules and a
Suricata-style subset of content rules, write alerts to JSONL, and show the
results in a Flask dashboard.

The code is intentionally compact so it can be read as a learning project. It
does not try to replace Suricata. The rule engine is a prototype
Snort/Suricata-like rule syntax subset, not a production-compatible
implementation.

## What It Does

- Reads packets from a PCAP file or captures live traffic with Scapy.
- Extracts normalized metadata such as IPs, ports, protocol, TCP flags, DNS
  query names, raw payload text, and common HTTP request fields.
- Detects behavior, anomaly, and signature patterns:
  - TCP port scans
  - ICMP ping floods
  - TCP SYN floods using SYN packets without ACK
  - DNS tunneling suspicion
- Parses and evaluates user-provided Suricata-style subset rules for common
  payload, HTTP, and DNS signatures.
- Stores alerts as newline-delimited JSON in `data/alerts.jsonl` by default.
- Shows alert counts, severity counts, top source IPs, and recent alerts in a
  Flask dashboard.
- Includes unit tests for behavior rules, rule parsing, sticky buffers, and
  thresholds.

## Requirements

- Python 3.10 or newer
- `scapy` for PCAP/live packet parsing
- `Flask` for the dashboard
- Root or administrator permissions for many live capture interfaces

Install dependencies from `requirements.txt`:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Quick Start

Generate demo alerts without needing real traffic:

```bash
python3 scripts/demo_events.py
```

Start the dashboard:

```bash
python3 dashboard/app.py
```

Open:

```text
http://127.0.0.1:5000
```

Run the tests:

```bash
python3 -m unittest discover -s tests
```

## Analyze A PCAP

Use `--pcap` to read packets from a capture file:

```bash
python3 main.py --pcap sample.pcap
```

By default alerts are appended to:

```text
data/alerts.jsonl
```

Use a different alert file:

```bash
python3 main.py --pcap sample.pcap --alerts data/lab-run.jsonl
```

## Live Capture

Use `--iface` to sniff a live interface:

```bash
sudo .venv/bin/python main.py --iface eth0 --limit 500
```

`--limit 0` means Scapy keeps sniffing until interrupted. Live capture often
requires elevated privileges because the process needs access to raw packets.

## Project Layout

```text
.
├── main.py                  # CLI entry point for PCAP/live capture
├── requirements.txt         # Python dependencies
├── nids/
│   ├── README.md            # Rule engine and core module details
│   ├── capture.py           # PCAP reader and live sniffer wrappers
│   ├── engine.py            # NIDS orchestration and counters
│   ├── models.py            # PacketEvent and Alert dataclasses
│   ├── parser.py            # Scapy packet normalization
│   ├── rules.py             # Behavior rules and Suricata-style subset engine
│   └── storage.py           # JSONL alert storage
├── dashboard/
│   ├── README.md            # Dashboard usage and data expectations
│   ├── app.py               # Flask application
│   ├── static/style.css     # Dashboard styles
│   └── templates/index.html # Dashboard page
├── scripts/
│   └── demo_events.py       # Synthetic events for local demos
└── tests/
    └── test_rules.py        # Unit tests for detection logic
```

## Runtime Flow

1. `main.py` receives either `--pcap` or `--iface`.
2. `nids.capture` reads packets and passes each Scapy packet to
   `nids.parser.packet_to_event`.
3. `packet_to_event` converts supported packets into a `PacketEvent`.
4. `NIDSEngine.process_event` updates counters and sends the event to
   `SlidingWindowRules.evaluate`.
5. `SlidingWindowRules` runs behavior/anomaly detections, then the
   Suricata-style subset rule engine.
6. Matching rules create `Alert` objects.
7. `AlertStore` appends each alert to JSONL.
8. `dashboard/app.py` reads the JSONL file and renders summary metrics plus the
   latest 100 alerts.

## Rule Engine Overview

The rule engine has two layers:

- Behavior detectors for stateful traffic patterns such as floods and port
  scans.
- A Suricata-style subset parser and matcher for signature rules.

Suricata-style subset rule text can be passed through
`RuleConfig.suricata_rules`, which makes it possible to keep behavior detections
enabled while loading a separate signature ruleset. DNS blacklist matching is
handled as a custom signature rule, not as a built-in behavior detector.

### Detection Rule Defaults

The built-in demo thresholds are active even when no custom signature rules are
loaded. They are lab/demo values, not production thresholds:

- `RULE-001` Port Scan: 20 unique TCP destination ports from one source in 10
  seconds (`detection_method: behavior`).
- `RULE-002` ICMP Ping Flood: 100 request-side ICMP packets from one source in
  10 seconds (`detection_method: behavior`).
- `RULE-003` TCP SYN Flood: 100 TCP SYN packets without ACK from one source to
  one destination service in 10 seconds (`detection_method: behavior`).
- `RULE-004` DNS Tunneling Suspicion: 5 suspicious DNS queries from one source
  in 30 seconds. A DNS query is suspicious if it has a query name of at least
  100 characters, a label of at least 45 characters, or a label of at least 24
  characters with Shannon entropy of at least 3.8
  (`detection_method: anomaly`).

Example:

```python
from nids.rules import RuleConfig, SlidingWindowRules

rules = SlidingWindowRules(
    RuleConfig(
        suricata_rules=(
            'alert http any any -> any 80 (msg:"Suspicious User Agent"; '
            'http.user_agent; content:"sqlmap"; nocase; '
            'classtype:attempted-recon; priority:2; sid:900001; rev:1;)',
        )
    )
)
```

Supported Suricata-style subset rule shape:

```text
action protocol src_ip src_port -> dst_ip dst_port (option:value; keyword;)
```

Supported header pieces:

- Actions: `alert`
- Protocols: `ip`, `tcp`, `udp`, `icmp`, `dns`, `http`, `http1`, `http2`,
  `tcp-pkt`
- Direction: `->`, `<-`, `<>`
- Addresses: `any`, single IPs, CIDR ranges, simple negation with `!`, and
  simple bracket lists
- Ports: `any`, single ports, ranges such as `1000:2000`, open ranges such as
  `:1024`, simple negation with `!`, and simple bracket lists

Prototype-supported options:

- `msg`
- `sid`
- `rev`
- `classtype`
- `priority`
- `flow`
- `content`
- `pcre`
- `nocase`
- `fast_pattern`
- `threshold`
- `detection_filter`
- Sticky buffers:
  - `pkt_data`
  - `raw_data`
  - `dns.query`
  - `http.method`
  - `http.uri`
  - `http.request_line`
  - `http.header`
  - `http.host`
  - `http.user_agent`

This project currently treats `fast_pattern` as rule metadata. It records the
keyword and exposes it in alert evidence, but it does not build a multi-pattern
prefilter like Suricata does. It also does not fully support `flow`,
`depth/offset`, `distance/within`, `flowbits`, `byte_test`, TCP stream
inspection, or `file_data`.

## Alert Format

Alerts are written as JSON objects, one per line:

```json
{
  "attack_type": "HTTP SQLi",
  "detection_method": "signature",
  "description": "10.0.0.5 matched Suricata rule 900002: HTTP SQLi",
  "destination_ip": "192.168.1.80",
  "evidence": {
    "action": "alert",
    "classtype": "unknown",
    "contents": [
      {
        "buffer": "http.uri",
        "fast_pattern": false,
        "nocase": true,
        "pattern": "union"
      }
    ],
    "protocol": "http",
    "rev": "1",
    "sid": "900002"
  },
  "rule_id": "900002",
  "severity": "Informational",
  "source_ip": "10.0.0.5",
  "timestamp": "2026-06-06T00:00:00+00:00"
}
```

Built-in rule `detection_method` values are `behavior` and `anomaly`.
Rules loaded through `RuleConfig.suricata_rules` use `signature`.

`priority` maps to severity:

- `1`: `High`
- `2`: `Medium`
- `3`: `Low`
- Missing or other values: `Informational`

## Current Limitations

- No IP defragmentation, TCP stream reassembly, or out-of-order segment
  handling.
- Payload split across multiple TCP segments, encoded, or obfuscated can evade
  simple content matching.
- TLS/HTTPS, DoH, and DoT contents are not visible unless the lab provides
  appropriate decrypted visibility.
- SPAN/TAP capture can lose packets or miss one side of asymmetric routing in
  real networks.
- Demo thresholds must be tuned against a real network baseline before any
  production-like use.
- DNS tunneling heuristics can false positive on legitimate CDN, tracking, DKIM,
  ACME challenge, or service-discovery domains; use whitelist, qtype,
  NXDOMAIN-rate, unique-subdomain, and reputation context in real deployments.

## Testing

Run all tests:

```bash
python3 -m unittest discover -s tests
```

Compile-check the Python files:

```bash
python3 -m compileall nids tests scripts dashboard main.py
```
