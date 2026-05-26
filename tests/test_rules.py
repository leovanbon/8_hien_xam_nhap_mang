from __future__ import annotations

import unittest

from nids.models import PacketEvent
from nids.rules import RuleConfig, SlidingWindowRules


def event(
    *,
    timestamp: float,
    src_ip: str = "10.0.0.5",
    dst_ip: str = "10.0.0.1",
    dst_port: int | None = None,
    protocol: str = "TCP",
    tcp_flags: str | None = None,
    dns_query: str | None = None,
) -> PacketEvent:
    return PacketEvent(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=44444,
        dst_port=dst_port,
        protocol=protocol,
        length=64,
        tcp_flags=tcp_flags,
        dns_query=dns_query,
    )


class RuleTests(unittest.TestCase):
    def test_port_scan_alerts_after_unique_port_threshold(self) -> None:
        rules = SlidingWindowRules(
            RuleConfig(port_scan_window_seconds=10, port_scan_unique_ports=3)
        )

        alerts = []
        for offset, port in enumerate([22, 80, 443]):
            alerts.extend(rules.evaluate(event(timestamp=float(offset), dst_port=port)))

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].attack_type, "Port Scan")

    def test_icmp_flood_alerts_after_packet_threshold(self) -> None:
        rules = SlidingWindowRules(
            RuleConfig(icmp_flood_window_seconds=10, icmp_flood_packet_count=3)
        )

        alerts = []
        for offset in range(3):
            alerts.extend(
                rules.evaluate(event(timestamp=float(offset), protocol="ICMP"))
            )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].attack_type, "ICMP Ping Flood")

    def test_syn_flood_alerts_after_syn_threshold(self) -> None:
        rules = SlidingWindowRules(
            RuleConfig(syn_flood_window_seconds=10, syn_flood_syn_count=3)
        )

        alerts = []
        for offset in range(3):
            alerts.extend(
                rules.evaluate(
                    event(timestamp=float(offset), dst_port=80, tcp_flags="S")
                )
            )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].attack_type, "TCP SYN Flood")

    def test_suspicious_dns_query_alerts(self) -> None:
        rules = SlidingWindowRules(
            RuleConfig(suspicious_domains={"malware.test"})
        )

        alerts = rules.evaluate(
            event(
                timestamp=1.0,
                protocol="DNS",
                dst_port=53,
                dns_query="dropper.malware.test",
            )
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].attack_type, "Suspicious DNS Query")


if __name__ == "__main__":
    unittest.main()
