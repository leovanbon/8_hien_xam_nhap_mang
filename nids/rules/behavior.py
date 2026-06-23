from __future__ import annotations

import math
from collections import defaultdict, deque

from nids.models import Alert, PacketEvent

from .config import RuleConfig
from .engine import SuricataRuleEngine


class SlidingWindowRules:
    _max_tracked_sources: int = 10_000

    def __init__(self, config: RuleConfig | None = None) -> None:
        self.config = config or RuleConfig()
        self.suricata = SuricataRuleEngine.from_config(self.config)
        self._dest_ports_by_src: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._icmp_by_src: dict[str, deque[float]] = defaultdict(deque)
        self._syn_by_service: dict[str, deque[float]] = defaultdict(deque)
        self._dns_tunnel_by_src: dict[str, deque[tuple[float, str, tuple[str, ...]]]] = (
            defaultdict(deque)
        )
        self._recent_alert_keys: dict[tuple[str, str], float] = {}
        self._cooldown_seconds = 5
        self._event_count = 0

    def evaluate(self, event: PacketEvent) -> list[Alert]:
        self._event_count += 1
        if self._event_count % 1000 == 0:
            self._cleanup_tracked_sources()
            self._cleanup_alert_keys(event.timestamp)

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

        dns_tunnel_alert = self._detect_dns_tunneling(event)
        if dns_tunnel_alert:
            alerts.append(dns_tunnel_alert)

        alerts.extend(self.suricata.evaluate(event))

        return alerts

    def _cleanup_tracked_sources(self) -> None:
        """LRU-style cleanup: when any tracking dict exceeds _max_tracked_sources,
        remove the oldest half of entries (those with the oldest timestamps)."""
        for src_dict in (
            self._dest_ports_by_src,
            self._icmp_by_src,
            self._syn_by_service,
            self._dns_tunnel_by_src,
        ):
            if len(src_dict) > self._max_tracked_sources:
                def _latest_ts(deq: deque) -> float:
                    if not deq:
                        return 0.0
                    last = deq[-1]
                    return last[0] if isinstance(last, tuple) else last

                sorted_keys = sorted(src_dict.keys(), key=lambda k: _latest_ts(src_dict[k]))
                to_remove = len(sorted_keys) // 2
                for key in sorted_keys[:to_remove]:
                    del src_dict[key]

    def _cleanup_alert_keys(self, now: float) -> None:
        """Remove alert cooldown entries older than _cooldown_seconds."""
        expired = [
            key for key, ts in self._recent_alert_keys.items()
            if now - ts > self._cooldown_seconds
        ]
        for key in expired:
            del self._recent_alert_keys[key]

    # TCP flag combinations used as port scan probes.
    # SYN  (S)   — standard connect/stealth scan (nmap -sS / -sT)
    # FIN  (F)   — FIN scan, evades simple SYN-only filters (nmap -sF)
    # NULL ()    — no flags set, bypasses stateless firewalls (nmap -sN)
    # XMAS (FPU) — FIN+PSH+URG "Christmas tree" scan (nmap -sX)
    # ACK scans need TCP state tracking to classify accurately, so this
    # prototype does not count bare ACK as a default scan probe.
    _SCAN_FLAGS: frozenset[str] = frozenset({"S", "F", "", "FPU"})

    def _detect_port_scan(self, event: PacketEvent) -> Alert | None:
        if event.protocol != "TCP" or event.dst_port is None:
            return None

        # Only count recognised probe flag patterns.
        # Response packets (RST, SYN-ACK, FIN-ACK, RST-ACK) go back to the
        # scanner's random per-probe source ports; counting them would make
        # the scanned host appear to be scanning back — a false positive.
        if event.tcp_flags not in self._SCAN_FLAGS:
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
            detection_method="behavior",
            severity="Medium",
            source_ip=event.src_ip,
            destination_ip=event.dst_ip,
            description=(
                f"{event.src_ip} contacted {len(unique_ports)} unique TCP ports "
                f"in {self.config.port_scan_window_seconds} seconds"
            ),
            evidence={"unique_ports": sorted(unique_ports), "count": len(unique_ports)},
        )

    # ICMP types that can be used as flood probes (request-side).
    # Type 8  — Echo Request      (ping flood, most common)
    # Type 13 — Timestamp Request (timestamp flood)
    # Type 17 — Address Mask Request (legacy, still abusable)
    # Their corresponding reply types (0, 14, 18) are excluded: counting
    # replies would make the victim appear to be flooding the attacker.
    _ICMP_FLOOD_TYPES: frozenset[int] = frozenset({8, 13, 17})

    def _detect_icmp_flood(self, event: PacketEvent) -> Alert | None:
        if event.protocol != "ICMP":
            return None

        # Only count request-side ICMP types that are used as flood vectors.
        # Reply types (0, 14, 18) go back to the attacker at the same rate
        # and must be excluded to avoid a false positive on the victim.
        if event.icmp_type not in self._ICMP_FLOOD_TYPES:
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
            detection_method="behavior",
            severity="High",
            source_ip=event.src_ip,
            destination_ip=event.dst_ip,
            description=(
                f"{event.src_ip} sent {len(window)} ICMP packets "
                f"in {self.config.icmp_flood_window_seconds} seconds"
            ),
            evidence={"icmp_packets": len(window)},
        )

    @staticmethod
    def _is_syn_without_ack(flags: str | None) -> bool:
        if flags is None:
            return False
        return "S" in flags and "A" not in flags

    def _detect_syn_flood(self, event: PacketEvent) -> Alert | None:
        if event.protocol != "TCP" or not self._is_syn_without_ack(event.tcp_flags):
            return None

        service_key = f"{event.src_ip or 'unknown'}:{event.dst_ip or 'unknown'}:{event.dst_port or 'unknown'}"
        window = self._syn_by_service[service_key]
        window.append(event.timestamp)
        self._drop_old_times(window, event.timestamp, self.config.syn_flood_window_seconds)

        if len(window) < self.config.syn_flood_syn_count:
            return None

        return self._alert_once(
            now=event.timestamp,
            rule_id="RULE-003",
            key=service_key,
            attack_type="TCP SYN Flood",
            detection_method="behavior",
            severity="High",
            source_ip=event.src_ip,
            destination_ip=event.dst_ip,
            description=(
                f"{event.src_ip} sent {len(window)} SYN packets without ACK "
                f"in {self.config.syn_flood_window_seconds} seconds"
            ),
            evidence={
                "syn_packets": len(window),
                "dst_ip": event.dst_ip,
                "dst_port": event.dst_port,
                "window_seconds": self.config.syn_flood_window_seconds,
                "service_key": service_key,
            },
        )

    def _detect_dns_tunneling(self, event: PacketEvent) -> Alert | None:
        if not event.dns_query:
            return None

        query = event.dns_query.lower().rstrip(".")
        reasons, query_length, max_label_length, max_label_entropy = self._dns_tunnel_features(query)
        if not reasons:
            return None

        window = self._dns_tunnel_by_src[event.src_ip or ""]
        window.append((event.timestamp, query, tuple(reasons)))
        while window and event.timestamp - window[0][0] > self.config.dns_tunnel_window_seconds:
            window.popleft()

        if len(window) < self.config.dns_tunnel_suspicious_count:
            return None

        recent_queries = [entry[1] for entry in window]
        reason_counts: dict[str, int] = defaultdict(int)
        for _, _, entry_reasons in window:
            for reason in entry_reasons:
                reason_counts[reason] += 1

        return self._alert_once(
            now=event.timestamp,
            rule_id="RULE-005",
            key=event.src_ip or "unknown",
            attack_type="DNS Tunneling Suspicion",
            detection_method="anomaly",
            severity="Medium",
            source_ip=event.src_ip,
            destination_ip=event.dst_ip,
            description=(
                f"{event.src_ip} sent {len(window)} DNS queries with tunneling "
                f"indicators in {self.config.dns_tunnel_window_seconds} seconds"
            ),
            evidence={
                "suspicious_queries": len(window),
                "suspicious_query_count": len(window),
                "window_seconds": self.config.dns_tunnel_window_seconds,
                "recent_queries": recent_queries[-5:],
                "reason_counts": dict(reason_counts),
                "latest_query": query,
                "query": query,
                "query_length": query_length,
                "max_label_length": max_label_length,
                "max_label_entropy": round(max_label_entropy, 3),
            },
        )

    def _dns_tunnel_features(self, query: str) -> tuple[list[str], int, int, float]:
        reasons: list[str] = []
        labels = [label for label in query.split(".") if label]
        longest_label = max((len(label) for label in labels), default=0)
        highest_entropy = max((self._shannon_entropy(label) for label in labels), default=0.0)

        if len(query) >= self.config.dns_tunnel_min_query_length:
            reasons.append("long_query_name")
        if longest_label >= self.config.dns_tunnel_min_label_length:
            reasons.append("long_label")
        if (
            longest_label >= self.config.dns_tunnel_entropy_label_length
            and highest_entropy >= self.config.dns_tunnel_min_label_entropy
        ):
            reasons.append("high_entropy_label")

        return reasons, len(query), longest_label, highest_entropy

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        counts: dict[str, int] = defaultdict(int)
        for char in value:
            counts[char] += 1
        length = len(value)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    def _alert_once(
        self,
        *,
        now: float,
        rule_id: str,
        key: str,
        attack_type: str,
        detection_method: str,
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
            detection_method=detection_method,
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
