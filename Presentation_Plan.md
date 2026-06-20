# NIDS Semester Project: Presentation Plan

**Target Duration:** 10-15 Minutes
**Target Audience:** Lecturer and Peers ("Intro to Cybersecurity")
**Goal:** Achieve an 'A' grade by clearly explaining the architecture, demonstrating deep understanding of intrusion detection concepts, and flawlessly executing a live demo.

---

## Slide 1: Title Slide (1 min)
*   **Content:** Project Title ("Custom Network Intrusion Detection System"), Course Name, Team Members.
*   **Talking Points:** Briefly introduce the team and state the core objective: building a lightweight NIDS from scratch to understand how enterprise tools like Suricata and Snort operate under the hood.

## Slide 2: Project Overview & Objectives (1.5 mins)
*   **Content:** Bullet points of the main goals (Packet Capture, Normalization, Dual-Engine Detection, Web Dashboard).
*   **Talking Points:** Explain that the system doesn't just read PCAPs, but sniffs live traffic. Emphasize the "Dual-Engine" approach—this is the most impressive technical feature of the project.

## Slide 3: System Architecture (2 mins)
*   **Content:** A block diagram (you can draw one) showing: `Network Interface -> Scapy Parser -> Engine (Behavior + Signature) -> JSONL Storage -> Flask Dashboard`.
*   **Talking Points:** Walk the audience through the lifecycle of a single packet. Mention why JSONL was chosen (easy to append, easy to parse for the dashboard).

## Slide 4: The Detection Engines: "Both Rules" (2 mins)
*   **Content:** Two columns comparing Behavior Rules vs. Signature Rules.
*   **Talking Points:** 
    *   *Behavioral:* Explain stateful tracking (e.g., sliding windows, counting SYN packets over 10 seconds). Mention the 5 built-in rules (Port Scan, Floods, DNS Tunneling).
    *   *Signature:* Explain the Suricata-style rule parser. Highlight how it performs Deep Packet Inspection (DPI) to match specific strings like SQL injection payloads or `sqlmap` user agents.

## Slide 5: Demo Environment Setup (1.5 mins)
*   **Content:** A simple network diagram showing the Host Machine (NIDS + Dashboard), Kali VM (Attacker), and Windows VM (Target).
*   **Talking Points:** Explain the separation of environments. The NIDS is running on the host, passively monitoring the virtual network interface connecting the Kali and Windows VMs. 

## Slide 6: LIVE DEMONSTRATION (5 mins)
*   **Action 1 (Setup):** Show the terminal where NIDS is starting with the custom rules file loaded. Open the Flask dashboard in the browser to show it's currently empty.
*   **Action 2 (Behavioral Attacks):** On Kali, run the first part of the attack script (`nmap`, `hping3`). Switch back to the dashboard to show the Port Scan and Flood alerts appearing in real-time.
*   **Action 3 (Signature Attacks):** On Kali, run the `curl` commands simulating SQL injections. Show the NIDS dashboard capturing these web attacks.
*   **Talking Points during Demo:** Keep the audience engaged. Explain *what* the Kali script is doing behind the scenes while the attacks are running. Point out the severities on the dashboard.

## Slide 7: Challenges & Learnings (1 min)
*   **Content:** 2-3 technical challenges faced.
*   **Talking Points:** Discuss issues like parsing raw packets efficiently with Scapy, implementing the sliding window logic, or writing the custom Suricata parser. This shows the lecturer that you learned from the process.

## Slide 8: Q&A (1 min)
*   **Content:** "Questions?" and links to the GitHub repo (if applicable).
*   **Talking Points:** Thank the audience and invite questions. Be prepared to answer how your NIDS differs from standard tools.
