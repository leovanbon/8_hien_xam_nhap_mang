import unittest

from src.detector import RuleBasedDetector


def packet(
    timestamp,
    protocol,
    src_ip="10.0.0.5",
    dst_ip="10.0.0.10",
    src_port=None,
    dst_port=None,
    payload="",
    tcp_flags=None,
):
    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "length": 64,
        "payload": payload,
        "src_port": src_port,
        "dst_port": dst_port,
        "tcp_flags": tcp_flags,
    }


class RuleBasedDetectorTest(unittest.TestCase):
    def test_detects_icmp_flood_inside_time_window(self):
        detector = RuleBasedDetector(icmp_threshold=3, icmp_window_seconds=10)

        alerts = []
        for offset in range(4):
            alerts.extend(detector.analyze(packet(100 + offset, "ICMP")))

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].category, "ICMP Flood")
        self.assertEqual(alerts[0].severity, "MEDIUM")

    def test_ignores_icmp_packets_outside_time_window(self):
        detector = RuleBasedDetector(icmp_threshold=3, icmp_window_seconds=2)

        alerts = []
        for timestamp in [100, 103, 106, 109]:
            alerts.extend(detector.analyze(packet(timestamp, "ICMP")))

        self.assertEqual(alerts, [])

    def test_detects_port_scan_by_distinct_destination_ports(self):
        detector = RuleBasedDetector(port_scan_threshold=3, port_scan_window_seconds=30)

        alerts = []
        for index, port in enumerate([20, 21, 22, 23]):
            alerts.extend(
                detector.analyze(
                    packet(
                        200 + index,
                        "TCP",
                        src_port=40000 + index,
                        dst_port=port,
                        tcp_flags="SYN",
                    )
                )
            )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].category, "Port Scan")
        self.assertIn("ports=20,21,22,23", alerts[0].evidence)

    def test_repeated_tcp_port_does_not_trigger_port_scan(self):
        detector = RuleBasedDetector(port_scan_threshold=3, port_scan_window_seconds=30)

        alerts = []
        for index in range(8):
            alerts.extend(
                detector.analyze(
                    packet(
                        300 + index,
                        "TCP",
                        src_port=50000 + index,
                        dst_port=80,
                        tcp_flags="SYN",
                    )
                )
            )

        self.assertEqual(alerts, [])

    def test_port_scan_ignores_tcp_responses_and_established_packets(self):
        detector = RuleBasedDetector(port_scan_threshold=1, port_scan_window_seconds=30)

        alerts = []
        alerts.extend(
            detector.analyze(
                packet(350, "TCP", src_port=80, dst_port=50000, tcp_flags="SYN-ACK")
            )
        )
        alerts.extend(
            detector.analyze(
                packet(351, "TCP", src_port=50000, dst_port=80, tcp_flags="ACK")
            )
        )

        self.assertEqual(alerts, [])

    def test_detects_payload_signatures(self):
        detector = RuleBasedDetector()

        alerts = detector.analyze(
            packet(
                400,
                "TCP",
                src_port=51515,
                dst_port=80,
                payload="GET /?id=1 UNION SELECT password FROM users HTTP/1.1",
            )
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].category, "SQL Injection")
        self.assertEqual(alerts[0].severity, "HIGH")


if __name__ == "__main__":
    unittest.main()
