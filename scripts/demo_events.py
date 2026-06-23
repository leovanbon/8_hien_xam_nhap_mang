from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nids.engine import NIDSEngine
from nids.models import PacketEvent
from nids.rules import RuleConfig, SlidingWindowRules
from nids.storage import AlertStore


def tcp_event(timestamp: float, src_ip: str, dst_port: int, flags: str | None = None) -> PacketEvent:
    return PacketEvent(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip="192.168.1.1",
        src_port=44000,
        dst_port=dst_port,
        protocol="TCP",
        length=60,
        tcp_flags=flags,
    )


def icmp_event(timestamp: float, src_ip: str) -> PacketEvent:
    return PacketEvent(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip="192.168.1.1",
        src_port=None,
        dst_port=None,
        protocol="ICMP",
        length=84,
        icmp_type=8,
    )


def dns_event(timestamp: float, src_ip: str, query: str) -> PacketEvent:
    return PacketEvent(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip="8.8.8.8",
        src_port=53000,
        dst_port=53,
        protocol="DNS",
        length=90,
        dns_query=query,
    )


def payload_event(timestamp: float, src_ip: str, payload_text: str) -> PacketEvent:
    return PacketEvent(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip="192.168.1.80",
        src_port=51000,
        dst_port=80,
        protocol="TCP",
        length=len(payload_text),
        payload_text=payload_text,
    )


def main() -> int:
    alert_path = Path("data/alerts.jsonl")
    alert_path.parent.mkdir(parents=True, exist_ok=True)
    alert_path.write_text("", encoding="utf-8")

    rules = SlidingWindowRules(
        RuleConfig(
            port_scan_unique_ports=5,
            icmp_flood_packet_count=5,
            syn_flood_syn_count=5,
            suricata_rules=(
                'alert tcp any any -> any 80 (msg:"SQL Injection Attempt"; '
                'content:"\' or \'1\'=\'1"; nocase; '
                'classtype:web-application-attack; priority:1; sid:900100; rev:1;)',
            ),
        )
    )
    engine = NIDSEngine(rules=rules, store=AlertStore(alert_path))

    events: list[PacketEvent] = []
    events.extend(tcp_event(float(i), "10.0.0.10", 20 + i) for i in range(5))
    events.extend(icmp_event(float(i), "10.0.0.20") for i in range(5))
    events.extend(tcp_event(float(i), "10.0.0.30", 80, "S") for i in range(5))
    events.append(dns_event(1.0, "10.0.0.40", "chatgpt.com"))
    events.append(
        payload_event(
            2.0,
            "10.0.0.50",
            "GET /index.php?id=' OR '1'='1 HTTP/1.1\r\nHost: example.test\r\n\r\n",
        )
    )
    events.extend(dns_event(float(i), "10.0.0.60", f"a{'b'*60}{i}.tunnel.example.com") for i in range(5))

    for event in events:
        for alert in engine.process_event(event):
            print(f"{alert.rule_id} [{alert.detection_method}] {alert.attack_type}: {alert.description}")

    print(f"\nWrote demo alerts to {alert_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
