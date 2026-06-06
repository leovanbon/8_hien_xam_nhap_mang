from __future__ import annotations

import unittest

from nids.models import PacketEvent
from nids.rules import RuleConfig, Signature, SlidingWindowRules, SuricataRuleParser


def event(
    *,
    timestamp: float,
    src_ip: str = "10.0.0.5",
    dst_ip: str = "10.0.0.1",
    dst_port: int | None = None,
    protocol: str = "TCP",
    tcp_flags: str | None = None,
    dns_query: str | None = None,
    payload_text: str | None = None,
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
        payload_text=payload_text,
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

    def test_dns_tunneling_suspicion_alerts_after_threshold(self) -> None:
        rules = SlidingWindowRules(
            RuleConfig(
                suspicious_domains=set(),
                dns_tunnel_window_seconds=10,
                dns_tunnel_suspicious_count=2,
                dns_tunnel_min_label_length=40,
            )
        )

        alerts = []
        for offset in range(2):
            alerts.extend(
                rules.evaluate(
                    event(
                        timestamp=float(offset),
                        protocol="DNS",
                        dst_port=53,
                        dns_query=f"{'a' * 42}{offset}.tunnel.example",
                    )
                )
            )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "RULE-005")
        self.assertEqual(alerts[0].attack_type, "DNS Tunneling Suspicion")
        self.assertEqual(alerts[0].evidence["suspicious_queries"], 2)
        self.assertIn("long_label", alerts[0].evidence["reason_counts"])

    def test_normal_dns_queries_do_not_trigger_tunneling_rule(self) -> None:
        rules = SlidingWindowRules(
            RuleConfig(
                suspicious_domains=set(),
                dns_tunnel_window_seconds=10,
                dns_tunnel_suspicious_count=2,
            )
        )

        alerts = []
        for offset, query in enumerate(["www.example.com", "api.example.com"]):
            alerts.extend(
                rules.evaluate(
                    event(
                        timestamp=float(offset),
                        protocol="DNS",
                        dst_port=53,
                        dns_query=query,
                    )
                )
            )

        self.assertEqual(alerts, [])

    def test_payload_signature_alerts(self) -> None:
        rules = SlidingWindowRules(
            RuleConfig(
                signatures=(
                    Signature(
                        rule_id="SIG-TEST",
                        attack_type="Test Signature",
                        severity="Medium",
                        pattern="bad-input",
                    ),
                )
            )
        )

        alerts = rules.evaluate(
            event(
                timestamp=1.0,
                dst_port=80,
                payload_text="GET /search?q=bad-input HTTP/1.1",
            )
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "SIG-TEST")

    def test_signature_can_match_specific_destination_port(self) -> None:
        rules = SlidingWindowRules(
            RuleConfig(
                signatures=(
                    Signature(
                        rule_id="SIG-HTTP",
                        attack_type="HTTP Signature",
                        severity="Medium",
                        pattern="sqlmap",
                        dst_port=80,
                    ),
                )
            )
        )

        no_match = rules.evaluate(
            event(timestamp=1.0, dst_port=22, payload_text="User-Agent: sqlmap")
        )
        match = rules.evaluate(
            event(timestamp=2.0, dst_port=80, payload_text="User-Agent: sqlmap")
        )

        self.assertEqual(no_match, [])
        self.assertEqual(len(match), 1)
        self.assertEqual(match[0].attack_type, "HTTP Signature")

    def test_parses_suricata_rule_header_and_options(self) -> None:
        rule = SuricataRuleParser.parse(
            'alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS '
            '(msg:"HTTP SQLi"; flow:established,to_server; http.uri; '
            'content:"/search"; fast_pattern; content:"union"; nocase; '
            "classtype:web-application-attack; priority:1; sid:900001; rev:2;)"
        )

        self.assertEqual(rule.header.protocol, "http")
        self.assertEqual(rule.header.direction, "->")
        self.assertEqual(rule.sid, "900001")
        self.assertEqual(rule.rev, "2")
        self.assertEqual(rule.severity, "High")
        self.assertEqual(rule.contents[0].buffer, "http.uri")
        self.assertTrue(rule.contents[0].fast_pattern)
        self.assertTrue(rule.contents[1].nocase)

    def test_suricata_http_sticky_buffer_rule_alerts(self) -> None:
        rules = SlidingWindowRules(
            RuleConfig(
                suricata_rules=(
                    'alert http any any -> any 80 (msg:"HTTP SQLi"; http.uri; '
                    'content:"union"; nocase; sid:900002; rev:1;)',
                )
            )
        )

        alerts = rules.evaluate(
            event(
                timestamp=1.0,
                dst_port=80,
                payload_text=(
                    "GET /search?q=UNION+SELECT HTTP/1.1\r\n"
                    "Host: example.test\r\n\r\n"
                ),
            )
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "900002")
        self.assertEqual(alerts[0].attack_type, "HTTP SQLi")

    def test_suricata_dns_sticky_buffer_rule_alerts(self) -> None:
        rules = SlidingWindowRules(
            RuleConfig(
                suspicious_domains=set(),
                suricata_rules=(
                    'alert dns any any -> any 53 (msg:"DNS bad query"; '
                    'dns.query; content:"bad.example"; nocase; sid:900003; rev:1;)',
                ),
            )
        )

        alerts = rules.evaluate(
            event(
                timestamp=1.0,
                protocol="DNS",
                dst_port=53,
                dns_query="Dropper.Bad.Example",
            )
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "900003")

    def test_suricata_detection_filter_tracks_threshold(self) -> None:
        rules = SlidingWindowRules(
            RuleConfig(
                suricata_rules=(
                    'alert tcp any any -> any 443 (msg:"Repeated TLS marker"; '
                    'content:"hello"; detection_filter:track by_src, count 3, seconds 10; '
                    "sid:900004; rev:1;)",
                )
            )
        )

        alerts = []
        for offset in range(3):
            alerts.extend(
                rules.evaluate(
                    event(
                        timestamp=float(offset),
                        dst_port=443,
                        payload_text="client hello",
                    )
                )
            )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "900004")


if __name__ == "__main__":
    unittest.main()
