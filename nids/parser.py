from __future__ import annotations

from typing import Any

from .models import PacketEvent


def scapy_available() -> bool:
    try:
        import scapy.all  # noqa: F401
    except ImportError:
        return False
    return True


def packet_to_event(packet: Any) -> PacketEvent | None:
    """Convert a Scapy packet into normalized metadata used by the rules."""
    try:
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.inet import ICMP, IP, TCP, UDP
    except ImportError as exc:
        raise RuntimeError("Scapy is required for packet parsing") from exc

    if IP not in packet:
        return None

    ip_layer = packet[IP]
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str | None = None
    dns_query: str | None = None
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
    )
