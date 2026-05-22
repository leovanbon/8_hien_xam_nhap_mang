from collections import defaultdict, deque
from typing import Deque, Dict, Hashable, Iterable, List, Optional, Set, Tuple

from src.alert import Alert


DEFAULT_SIGNATURES = {
    "SQL Injection": ["union select", "drop table", "' or '1'='1", "\" or \"1\"=\"1"],
    "Cross-Site Scripting": ["<script>", "javascript:", "onerror="],
    "Path Traversal": ["../", "..\\", "/etc/passwd", "boot.ini"],
}


class RuleBasedDetector:
    def __init__(
        self,
        icmp_threshold: int = 10,
        icmp_window_seconds: int = 10,
        port_scan_threshold: int = 10,
        port_scan_window_seconds: int = 30,
        signatures: Optional[Dict[str, Iterable[str]]] = None,
    ):
        self.icmp_threshold = icmp_threshold
        self.icmp_window_seconds = icmp_window_seconds
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window_seconds = port_scan_window_seconds
        self.signatures = {
            category: [signature.lower() for signature in values]
            for category, values in (signatures or DEFAULT_SIGNATURES).items()
        }

        self._icmp_events: Dict[str, Deque[float]] = defaultdict(deque)
        self._tcp_port_events: Dict[Tuple[str, str], Deque[Tuple[float, int]]] = defaultdict(deque)
        self._last_icmp_alert: Dict[str, float] = {}
        self._last_port_scan_alert: Dict[Tuple[str, str], float] = {}

    def analyze(self, packet_data: Optional[dict]) -> List[Alert]:
        if not packet_data:
            return []

        alerts = []
        protocol = packet_data.get("protocol")

        if protocol == "ICMP":
            alerts.extend(self._detect_icmp_flood(packet_data))

        if protocol == "TCP":
            alerts.extend(self._detect_port_scan(packet_data))

        alerts.extend(self._detect_payload_signatures(packet_data))
        return alerts

    def _detect_icmp_flood(self, packet_data: dict) -> List[Alert]:
        src_ip = packet_data["src_ip"]
        timestamp = packet_data["timestamp"]
        events = self._icmp_events[src_ip]
        events.append(timestamp)
        self._drop_old_events(events, timestamp, self.icmp_window_seconds)

        if len(events) <= self.icmp_threshold:
            return []

        if self._alert_was_recent(self._last_icmp_alert, src_ip, timestamp, self.icmp_window_seconds):
            return []

        self._last_icmp_alert[src_ip] = timestamp
        return [
            self._make_alert(
                packet_data,
                "MEDIUM",
                "ICMP Flood",
                f"More than {self.icmp_threshold} ICMP packets in "
                f"{self.icmp_window_seconds} seconds",
                evidence=f"count={len(events)}",
            )
        ]

    def _detect_port_scan(self, packet_data: dict) -> List[Alert]:
        dst_port = packet_data.get("dst_port")
        if dst_port is None:
            return []

        tcp_flags = packet_data.get("tcp_flags") or ""
        if "SYN" not in tcp_flags or "ACK" in tcp_flags:
            return []

        src_ip = packet_data["src_ip"]
        dst_ip = packet_data["dst_ip"]
        timestamp = packet_data["timestamp"]
        scan_key = (src_ip, dst_ip)
        events = self._tcp_port_events[scan_key]
        events.append((timestamp, dst_port))

        while events and timestamp - events[0][0] > self.port_scan_window_seconds:
            events.popleft()

        unique_ports: Set[int] = {port for _, port in events}
        if len(unique_ports) <= self.port_scan_threshold:
            return []

        if self._alert_was_recent(
            self._last_port_scan_alert,
            scan_key,
            timestamp,
            self.port_scan_window_seconds,
        ):
            return []

        self._last_port_scan_alert[scan_key] = timestamp
        return [
            self._make_alert(
                packet_data,
                "HIGH",
                "Port Scan",
                f"Connections to more than {self.port_scan_threshold} distinct TCP ports "
                f"in {self.port_scan_window_seconds} seconds",
                evidence=f"ports={','.join(str(port) for port in sorted(unique_ports))}",
            )
        ]

    def _detect_payload_signatures(self, packet_data: dict) -> List[Alert]:
        payload = (packet_data.get("payload") or "").lower()
        if not payload:
            return []

        alerts = []
        for category, signatures in self.signatures.items():
            for signature in signatures:
                if signature in payload:
                    alerts.append(
                        self._make_alert(
                            packet_data,
                            "HIGH",
                            category,
                            f"Payload matched suspicious signature '{signature}'",
                            evidence=signature,
                        )
                    )
                    break

        return alerts

    def _make_alert(
        self,
        packet_data: dict,
        severity: str,
        category: str,
        message: str,
        evidence: Optional[str] = None,
    ) -> Alert:
        return Alert(
            timestamp=packet_data["timestamp"],
            severity=severity,
            category=category,
            message=message,
            src_ip=packet_data["src_ip"],
            dst_ip=packet_data["dst_ip"],
            protocol=packet_data["protocol"],
            src_port=packet_data.get("src_port"),
            dst_port=packet_data.get("dst_port"),
            evidence=evidence,
        )

    @staticmethod
    def _drop_old_events(events: Deque[float], now: float, window_seconds: int) -> None:
        while events and now - events[0] > window_seconds:
            events.popleft()

    @staticmethod
    def _alert_was_recent(
        last_alerts: Dict[Hashable, float],
        key: Hashable,
        now: float,
        cooldown_seconds: int,
    ) -> bool:
        return key in last_alerts and now - last_alerts[key] <= cooldown_seconds
