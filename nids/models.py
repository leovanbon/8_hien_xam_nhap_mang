from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class PacketEvent:
    timestamp: float
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str
    length: int
    tcp_flags: str | None = None
    icmp_type: int | None = None
    dns_query: str | None = None
    payload_text: str | None = None
    http_method: str | None = None
    http_uri: str | None = None
    http_host: str | None = None
    http_user_agent: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Alert:
    timestamp: str
    rule_id: str
    attack_type: str
    severity: str
    source_ip: str | None
    destination_ip: str | None
    description: str
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def create(
        cls,
        *,
        rule_id: str,
        attack_type: str,
        severity: str,
        source_ip: str | None,
        destination_ip: str | None,
        description: str,
        evidence: dict[str, Any],
    ) -> "Alert":
        return cls(
            timestamp=utc_now_iso(),
            rule_id=rule_id,
            attack_type=attack_type,
            severity=severity,
            source_ip=source_ip,
            destination_ip=destination_ip,
            description=description,
            evidence=evidence,
        )
