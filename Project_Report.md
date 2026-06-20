# Network Intrusion Detection System (NIDS) Semester Project Report

## 1. Executive Summary

This project implements a lightweight Network Intrusion Detection System
(NIDS) in Python. The system reads packets from a PCAP file or a live network
interface, normalizes them into structured events, applies detection rules, and
stores alerts for visualization through a Flask dashboard.

The main focus of the project is not to replace production tools such as
Suricata or Zeek. Instead, it demonstrates the core design of a NIDS: packet
capture, protocol parsing, stateful behavior detection, signature matching,
alert storage, and dashboard-based monitoring.

## 2. Project Scope and Objectives

The project focuses on a detection-only NIDS with the following objectives:

* **Packet capture and normalization:** Read network traffic using Scapy and
  convert supported packets into a common `PacketEvent` structure.
* **Behavior-based detection:** Detect simple stateful patterns such as port
  scans, ICMP floods, TCP SYN floods, suspicious DNS queries, and DNS tunneling
  indicators.
* **Signature-based detection:** Parse and evaluate a subset of Suricata-style
  rules for payload, HTTP, and DNS fields.
* **Alert persistence:** Store generated alerts as JSON Lines so they can be
  appended and processed efficiently.
* **Visualization:** Provide a Flask dashboard showing alert counts, severity
  distribution, top source IPs, and recent alerts.

The system is designed for learning and demonstration. It does not perform
inline blocking, TLS decryption, TCP stream reassembly, or high-throughput
packet processing for enterprise networks.

## 3. System Architecture

The NIDS is organized as a pipeline:

1. **Capture (`nids/capture.py`):** Reads packets from a PCAP file or sniffs a
   live interface with Scapy.
2. **Parser (`nids/parser.py`):** Extracts source/destination IPs, ports,
   protocol, TCP flags, ICMP type, DNS query names, raw payload text, and common
   HTTP request fields.
3. **Detection Engine (`nids/engine.py`, `nids/rules/`):** Runs built-in
   behavior rules and user-provided Suricata-style signature rules.
4. **Storage (`nids/storage.py`):** Writes alerts to JSONL.
5. **Dashboard (`dashboard/app.py`):** Reads the JSONL file and renders summary
   metrics and recent alerts.

This separation keeps the implementation easy to inspect and test: capture and
parsing are separated from detection logic, while alert storage is separated
from visualization.

## 4. Detection Capabilities

### 4.1 Behavior Rules

The behavior engine uses sliding time windows and per-source counters:

* **RULE-001 Port Scan:** 20 unique TCP destination ports from one source
  within 10 seconds.
* **RULE-002 ICMP Ping Flood:** 100 ICMP echo-request packets from one source
  within 10 seconds.
* **RULE-003 TCP SYN Flood:** 100 TCP SYN packets from one source within 10
  seconds.
* **RULE-004 Suspicious DNS Query:** Exact or subdomain match against known
  suspicious domains such as `malware.test` and `phishing.test`.
* **RULE-005 DNS Tunneling Suspicion:** Repeated DNS queries with long labels or
  high-entropy labels within a short time window.

### 4.2 Suricata-Style Signature Rules

The signature engine supports a practical subset of Suricata rule syntax:

* Rule headers with action, protocol, addresses, ports, and direction.
* Options such as `msg`, `sid`, `rev`, `classtype`, `priority`, `flow`,
  `content`, `pcre`, `nocase`, `threshold`, and `detection_filter`.
* Sticky buffers such as `pkt_data`, `raw_data`, `dns.query`, `http.uri`, and
  `http.user_agent`.

The demo rules in `custom.rules` detect:

* SQL injection content in an HTTP URI.
* `sqlmap` scanner indicators in the `User-Agent` header.
* SQL injection content in raw HTTP POST data.

## 5. Demonstration and Evaluation

The demo environment uses three roles:

1. **Host machine:** Runs the NIDS engine and dashboard.
2. **Kali Linux VM:** Generates test traffic using tools such as `nmap`,
   `hping3`, `dig`, and `curl`.
3. **Target VM:** Receives scan, flood, DNS, and HTTP test traffic.

The attack script exercises both detection layers:

* `nmap` SYN scan triggers the port scan rule.
* `hping3` ICMP traffic triggers the ping flood rule.
* `hping3` SYN traffic triggers the SYN flood rule.
* `dig` queries trigger suspicious DNS and DNS tunneling rules.
* `curl` requests trigger custom HTTP signature rules.

The results show that the implemented rules can generate the expected alerts in
the controlled lab scenario. This validates the project design for educational
use, while still leaving room for more complete protocol handling and
performance optimization.

## 6. Limitations

The current implementation has several important limitations:

* It is an IDS, not an IPS: it alerts but does not block traffic.
* It does not decrypt HTTPS/TLS traffic.
* It does not perform full TCP stream reassembly.
* Payload inspection is capped to keep memory and matching cost bounded.
* Python and Scapy are appropriate for a semester project but are not suitable
  for multi-gigabit production traffic without major redesign.
* Detection quality depends on rule thresholds and the completeness of the
  signature set.

## 7. Conclusion

The project successfully demonstrates the core workflow of a NIDS: capture,
normalization, behavior detection, signature matching, alert storage, and
dashboard visualization. It is most valuable as a learning system for
understanding how IDS components interact and how different detection methods
complement each other.

Future improvements should prioritize TCP stream reassembly, richer protocol
parsing, better rule compatibility, baseline tuning, automated response
integration, and performance-oriented packet capture.

## 8. References

* [Suricata Rules Format](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html)
* [Scapy Documentation](https://scapy.net/)
* [Flask Web Framework](https://flask.palletsprojects.com/)
