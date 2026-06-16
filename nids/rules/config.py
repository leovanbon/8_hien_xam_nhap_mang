from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Signature:
    """Legacy signature API kept for existing callers.

    New rules should prefer Suricata-style text in RuleConfig.suricata_rules.
    """

    rule_id: str
    attack_type: str
    severity: str
    pattern: str
    field: str = "payload_text"
    protocol: str | None = None
    dst_port: int | None = None
    case_sensitive: bool = False


def default_signatures() -> tuple[Signature, ...]:
    return ()


def default_suricata_rules() -> tuple[str, ...]:
    return ()


@dataclass(frozen=True)
class RuleConfig:
    port_scan_window_seconds: int = 10
    port_scan_unique_ports: int = 20
    icmp_flood_window_seconds: int = 10
    icmp_flood_packet_count: int = 100
    syn_flood_window_seconds: int = 10
    syn_flood_syn_count: int = 100
    dns_tunnel_window_seconds: int = 30
    dns_tunnel_suspicious_count: int = 5
    dns_tunnel_min_query_length: int = 100
    dns_tunnel_min_label_length: int = 45
    dns_tunnel_min_label_entropy: float = 3.8
    dns_tunnel_entropy_label_length: int = 24
    suspicious_domains: set[str] = field(
        default_factory=lambda: {
            "malware.test",
            "phishing.test",
            "bad-domain.example",
        }
    )
    signatures: tuple[Signature, ...] = field(default_factory=default_signatures)
    suricata_rules: tuple[str, ...] = field(default_factory=default_suricata_rules)
