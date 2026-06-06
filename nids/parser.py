from __future__ import annotations

from typing import Any

from .models import PacketEvent


def scapy_available() -> bool:
    try:
        import scapy.all  # noqa: F401
    except ImportError:
        return False
    return True


def parse_http_payload(payload_text: str | None) -> dict[str, str | None]:
    if not payload_text:
        return {
            "http_method": None,
            "http_uri": None,
            "http_host": None,
            "http_user_agent": None,
        }

    lines = payload_text.splitlines()
    request_line = lines[0] if lines else ""
    parts = request_line.split()
    method = parts[0] if len(parts) >= 2 and parts[0].isalpha() else None
    uri = parts[1] if method else None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            break
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()

    return {
        "http_method": method,
        "http_uri": uri,
        "http_host": headers.get("host"),
        "http_user_agent": headers.get("user-agent"),
    }


def packet_to_event(packet: Any) -> PacketEvent | None:
    """Convert a Scapy packet into normalized metadata used by the rules."""
    try:
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.packet import Raw
    except ImportError as exc:
        raise RuntimeError("Scapy is required for packet parsing") from exc

    if IP not in packet:
        return None

    ip_layer = packet[IP]
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str | None = None
    dns_query: str | None = None
    payload_text: str | None = None
    protocol = str(ip_layer.proto)

    if TCP in packet:
        tcp_layer = packet[TCP]
        protocol = "TCP"
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)
        tcp_flags = str(tcp_layer.flags)
    elif UDP in packet:
        udp_layer = packet[UDP]
        protocol = "UDP"
        src_port = int(udp_layer.sport)
        dst_port = int(udp_layer.dport)
    elif ICMP in packet:
        protocol = "ICMP"

    if DNS in packet and packet[DNS].qd is not None:
        query = packet[DNSQR].qname
        dns_query = query.decode(errors="replace").rstrip(".")
        protocol = "DNS"

    if Raw in packet:
        raw_bytes = bytes(packet[Raw].load)
        payload_text = raw_bytes[:2048].decode("utf-8", errors="replace")

    http_fields = parse_http_payload(payload_text)

    return PacketEvent(
        timestamp=float(packet.time),
        src_ip=str(ip_layer.src),
        dst_ip=str(ip_layer.dst),
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=len(packet),
        tcp_flags=tcp_flags,
        dns_query=dns_query,
        payload_text=payload_text,
        http_method=http_fields["http_method"],
        http_uri=http_fields["http_uri"],
        http_host=http_fields["http_host"],
        http_user_agent=http_fields["http_user_agent"],
    )
