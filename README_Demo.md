# NIDS Demo Execution Guide

Follow these exact steps during your presentation to demonstrate behavior,
anomaly, built-in DNS signature, and Suricata-style signature rules working together in an
isolated lab. Do not run the flood commands on networks or systems you do not
own or have explicit permission to test.

## Prerequisites
1.  **Host Machine:** Where this code resides. You need Python 3.10+ installed.
2.  **Kali Linux VM:** The attacker. Needs network connectivity to the Target VM.
3.  **Windows VM:** The target. Must be running a simple HTTP server on port 80 (e.g., `python -m http.server 80` or XAMPP) to trigger the HTTP signature rules.

*Note: Ensure your Host Machine's virtual network interface (e.g., `vmnet8`, `vboxnet0`, `virbr0`) can see the traffic between the Kali VM and Windows VM.*

## Step 1: Start the Dashboard on the Host
Open a terminal on your Host Machine and start the Flask web dashboard:
```bash
cd /home/bon/8_hien_xam_nhap_mang
source .venv/bin/activate
python3 dashboard/app.py
```
*   Open your browser and navigate to `http://127.0.0.1:5000`. It should show zero alerts.

## Step 2: Start the NIDS Engine on the Host
Open a second terminal on your Host Machine. You need to start the NIDS engine, passing it the network interface that connects your VMs, and the `custom.rules` file to load the signature rules alongside the behavior rules.
```bash
cd /home/bon/8_hien_xam_nhap_mang
source .venv/bin/activate

# Replace <YOUR_INTERFACE> with the actual virtual network interface (e.g., vmnet1, virbr0)
sudo .venv/bin/python main.py --iface <YOUR_INTERFACE> --rules custom.rules --limit 0
```
*   The terminal should print: `Loaded 3 Suricata-style rule(s) from custom.rules`. NIDS is now listening!

## Step 3: Run the Attack Script from Kali
Switch over to your Kali Linux VM.
Ensure you have copied the `scripts/kali_attack_demo.sh` script to the Kali VM.

Execute the script, passing the IP address of your Windows VM:
```bash
chmod +x kali_attack_demo.sh
sudo ./kali_attack_demo.sh <WINDOWS_VM_IP>
```

*   The script will systematically run through 6 lab scenarios:
    1.  **Port Scan (Nmap):** Triggers Behavior RULE-001.
    2.  **ICMP Ping Flood (Hping3):** Triggers behavior RULE-002.
    3.  **TCP SYN Flood (Hping3):** Triggers behavior RULE-003 using SYN packets without ACK.
    4.  **Suspicious DNS (Dig):** Triggers built-in DNS signature RULE-004.
    5.  **DNS Tunneling (Dig):** Triggers anomaly RULE-005.
    6.  **HTTP Signature Attacks (Curl):** Triggers your `custom.rules` Suricata-style subset signatures (SQL Injection and sqlmap).

## Step 4: Show the Results
1.  **Host Terminal:** You will see the NIDS printing out the alerts in real-time as the Kali script progresses.
2.  **Web Dashboard:** Refresh your browser at `http://127.0.0.1:5000`. Review the alert counts, severity distribution, top sources, and recent alert rows. Record the observed alert counts for the presentation results table instead of inventing numbers.
