from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field

from .models import Alert, PacketEvent


@dataclass(frozen=True)
class RuleConfig:
    port_scan_window_seconds: int = 10
    port_scan_unique_ports: int = 20
    icmp_flood_window_seconds: int = 10
    icmp_flood_packet_count: int = 100
    syn_flood_window_seconds: int = 10
    syn_flood_syn_count: int = 100
    suspicious_domains: set[str] = field(
        default_factory=lambda: {
            "malware.test",
            "phishing.test",
            "bad-domain.example",
        }
    )


class SlidingWindowRules:
    def __init__(self, config: RuleConfig | None = None) -> None:
        self.config = config or RuleConfig()
        self._dest_ports_by_src: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._icmp_by_src: dict[str, deque[float]] = defaultdict(deque)
        self._syn_by_src: dict[str, deque[float]] = defaultdict(deque)
        self._recent_alert_keys: dict[tuple[str, str], float] = {}
        self._cooldown_seconds = 5

    def evaluate(self, event: PacketEvent) -> list[Alert]:
        alerts: list[Alert] = []
        if not event.src_ip:
            return alerts

        port_scan_alert = self._detect_port_scan(event)
        if port_scan_alert:
            alerts.append(port_scan_alert)

        icmp_alert = self._detect_icmp_flood(event)
        if icmp_alert:
            alerts.append(icmp_alert)

        syn_alert = self._detect_syn_flood(event)
        if syn_alert:
            alerts.append(syn_alert)

        dns_alert = self._detect_suspicious_dns(event)
        if dns_alert:
            alerts.append(dns_alert)

        return alerts

    def _detect_port_scan(self, event: PacketEvent) -> Alert | None:
        if event.protocol != "TCP" or event.dst_port is None:
            return None

        window = self._dest_ports_by_src[event.src_ip or ""]
        window.append((event.timestamp, event.dst_port))
        self._drop_old_ports(window, event.timestamp, self.config.port_scan_window_seconds)

        unique_ports = {port for _, port in window}
        if len(unique_ports) < self.config.port_scan_unique_ports:
            return None

        return self._alert_once(
            now=event.timestamp,
            rule_id="RULE-001",
            key=event.src_ip or "unknown",
            attack_type="Port Scan",
            severity="Medium",
            source_ip=event.src_ip,
            destination_ip=event.dst_ip,
            description=(
                f"{event.src_ip} contacted {len(unique_ports)} unique TCP ports "
                f"in {self.config.port_scan_window_seconds} seconds"
            ),
            evidence={"unique_ports": sorted(unique_ports), "count": len(unique_ports)},
        )

    def _detect_icmp_flood(self, event: PacketEvent) -> Alert | None:
        if event.protocol != "ICMP":
            return None

        window = self._icmp_by_src[event.src_ip or ""]
        window.append(event.timestamp)
        self._drop_old_times(window, event.timestamp, self.config.icmp_flood_window_seconds)

        if len(window) < self.config.icmp_flood_packet_count:
            return None

        return self._alert_once(
            now=event.timestamp,
            rule_id="RULE-002",
            key=event.src_ip or "unknown",
            attack_type="ICMP Ping Flood",
            severity="High",
            source_ip=event.src_ip,
            destination_ip=event.dst_ip,
            description=(
                f"{event.src_ip} sent {len(window)} ICMP packets "
                f"in {self.config.icmp_flood_window_seconds} seconds"
            ),
            evidence={"icmp_packets": len(window)},
        )

    def _detect_syn_flood(self, event: PacketEvent) -> Alert | None:
        if event.protocol != "TCP" or event.tcp_flags != "S":
            return None

        window = self._syn_by_src[event.src_ip or ""]
        window.append(event.timestamp)
        self._drop_old_times(window, event.timestamp, self.config.syn_flood_window_seconds)

        if len(window) < self.config.syn_flood_syn_count:
            return None

        return self._alert_once(
            now=event.timestamp,
            rule_id="RULE-003",
            key=event.src_ip or "unknown",
            attack_type="TCP SYN Flood",
            severity="High",
            source_ip=event.src_ip,
            destination_ip=event.dst_ip,
            description=(
                f"{event.src_ip} sent {len(window)} SYN packets "
                f"in {self.config.syn_flood_window_seconds} seconds"
            ),
            evidence={"syn_packets": len(window)},
        )

    def _detect_suspicious_dns(self, event: PacketEvent) -> Alert | None:
        if not event.dns_query:
            return None

        query = event.dns_query.lower()
        suspicious_match = next(
            (
                domain
                for domain in self.config.suspicious_domains
                if query == domain or query.endswith(f".{domain}")
            ),
            None,
        )
        if not suspicious_match:
            return None

        return self._alert_once(
            now=event.timestamp,
            rule_id="RULE-004",
            key=f"{event.src_ip}:{query}",
            attack_type="Suspicious DNS Query",
            severity="Medium",
            source_ip=event.src_ip,
            destination_ip=event.dst_ip,
            description=f"{event.src_ip} queried suspicious domain {query}",
            evidence={"query": query, "matched_domain": suspicious_match},
        )

    def _alert_once(
        self,
        *,
        now: float,
        rule_id: str,
        key: str,
        attack_type: str,
        severity: str,
        source_ip: str | None,
        destination_ip: str | None,
        description: str,
        evidence: dict,
    ) -> Alert | None:
        alert_key = (rule_id, key)
        last_alert = self._recent_alert_keys.get(alert_key)
        if last_alert is not None and now - last_alert < self._cooldown_seconds:
            return None

        self._recent_alert_keys[alert_key] = now
        return Alert.create(
            rule_id=rule_id,
            attack_type=attack_type,
            severity=severity,
            source_ip=source_ip,
            destination_ip=destination_ip,
            description=description,
            evidence=evidence,
        )

    @staticmethod
    def _drop_old_ports(window: deque[tuple[float, int]], now: float, seconds: int) -> None:
        while window and now - window[0][0] > seconds:
            window.popleft()

    @staticmethod
    def _drop_old_times(window: deque[float], now: float, seconds: int) -> None:
        while window and now - window[0] > seconds:
            window.popleft()
