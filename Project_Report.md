# Network Intrusion Detection System (NIDS) Semester Project Report

## 1. Executive Summary
This report details the design, implementation, and evaluation of a custom Network Intrusion Detection System (NIDS) developed for the "Intro to Cybersecurity" course. The project demonstrates a functional, lightweight NIDS capable of monitoring network traffic, analyzing it for malicious activities, and alerting administrators through a web-based dashboard. The system employs a dual-engine approach, combining stateful behavior analysis with signature-based detection (Suricata-style rules) to provide robust security monitoring.

## 2. Project Objectives
*   **Packet Capture & Normalization:** Capture live network traffic and parse it into normalized metadata (IPs, ports, protocols, payloads).
*   **Behavioral Detection:** Identify stateful attacks such as floods, port scans, and suspicious DNS activities based on predefined thresholds.
*   **Signature-Based Detection:** Implement a Suricata-style rule engine to detect known attack signatures in packet payloads and protocol headers.
*   **Visualization:** Provide a user-friendly dashboard to display alerts, metrics, and network statistics in real-time.

## 3. System Architecture
The NIDS is built using Python 3 and consists of several key components:

1.  **Capture Engine (`capture.py`, `parser.py`):** Utilizes `scapy` to sniff live traffic from a designated network interface or read from PCAP files. It normalizes raw packets into structured `PacketEvent` objects.
2.  **Detection Engine (`engine.py`, `rules.py`):** The core component that processes events through two layers:
    *   **Sliding Window Behavior Rules:** Tracks connections and packet rates to detect anomalies like TCP SYN floods or ICMP ping floods.
    *   **Signature Engine:** Parses and evaluates user-provided Suricata-style rules against packet metadata and raw payloads.
3.  **Alert Storage (`storage.py`):** Logs generated alerts in JSON Lines (JSONL) format for easy parsing and persistence.
4.  **Web Dashboard (`app.py`):** A Flask-based web application that visualizes the JSONL alerts, displaying severity breakdowns, top attackers, and recent intrusion events.

## 4. Detection Capabilities (The Dual-Engine Rules)
Our NIDS effectively utilizes **both** behavioral and signature rules to maximize detection coverage.

### 4.1. Behavior Rules
These rules monitor traffic patterns over time (sliding windows):
*   **RULE-001 (Port Scan):** Triggers when a single source attempts to connect to 20 unique TCP destination ports within 10 seconds.
*   **RULE-002 (ICMP Ping Flood):** Detects volumetric denial-of-service by triggering on 100 ICMP packets from one source in 10 seconds.
*   **RULE-003 (TCP SYN Flood):** Identifies resource exhaustion attacks (100 SYN packets in 10 seconds).
*   **RULE-004 (Suspicious DNS):** Flags queries to known malicious domains (`malware.test`, etc.).
*   **RULE-005 (DNS Tunneling):** Uses heuristics (entropy, label length) to detect data exfiltration via DNS.

### 4.2. Signature Rules (Suricata-Style)
These rules perform deep packet inspection (DPI) to match specific byte sequences or protocol anomalies:
*   **HTTP URI SQL Injection:** Detects malicious SQL payloads in the requested URL.
*   **sqlmap Scanner:** Identifies automated vulnerability scanners via the `User-Agent` header.
*   **HTTP POST SQL Injection:** Inspects raw packet data (`pkt_data`) for SQL injection attempts in form submissions.

## 5. Demonstration Scenario
To validate the system, an attack simulation was conducted using three distinct environments:
1.  **Host Machine:** Runs the NIDS engine (`main.py`) listening on the virtual network interface and hosts the Flask dashboard.
2.  **Kali Linux VM (Attacker):** Executes a custom bash script (`kali_attack_demo.sh`) utilizing tools like `nmap`, `hping3`, `dig`, and `curl` to generate malicious traffic.
3.  **Windows VM (Target):** Acts as the victim machine running standard services (e.g., HTTP on port 80) to receive the attacks.

### Attack Execution Flow
*   **Reconnaissance:** Kali VM runs an aggressive `nmap` SYN scan, triggering the NIDS Port Scan behavior rule (RULE-001).
*   **Denial of Service (DoS):** Kali VM uses `hping3` to launch ICMP and TCP SYN floods, triggering RULE-002 and RULE-003.
*   **Exfiltration / C2:** Kali VM uses `dig` to query suspicious domains and simulate DNS tunneling with high-entropy subdomains (RULE-004, RULE-005).
*   **Web Exploitation:** Kali VM sends crafted HTTP requests containing SQL injection payloads and `sqlmap` signatures, which are successfully caught by the NIDS signature engine.

## 6. Conclusion
The developed NIDS successfully meets all project requirements, demonstrating the ability to perform live packet capture, behavioral analysis, and signature matching. The system provides a clear, actionable dashboard for monitoring, making it an effective educational tool for understanding network security monitoring principles.

## 7. References
*   [Suricata Rules Format](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html)
*   [Scapy Documentation](https://scapy.net/)
*   [Flask Web Framework](https://flask.palletsprojects.com/)
