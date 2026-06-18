from __future__ import annotations

import logging
from typing import Any

from .models import PacketEvent
from .http_utils import parse_http_payload

logger = logging.getLogger(__name__)


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
        from scapy.packet import Raw
    except ImportError as exc:
        raise RuntimeError("Scapy is required for packet parsing") from exc

    if IP not in packet:
        return None

    ip_layer = packet[IP]
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str | None = None
    icmp_type: int | None = None
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
        # Store the ICMP type so detectors can distinguish echo requests
        # (type 8) from echo replies (type 0) and avoid false positives on
        # the victim host when it replies to a flood.
        icmp_type = int(packet[ICMP].type)

    if DNS in packet and packet[DNS].qd is not None:
        # Only extract the query name from DNS *query* packets (qr == 0).
        # DNS *response* packets (qr == 1) also carry the original question
        # section, so without this check the upstream resolver (e.g. 8.8.8.8)
        # would appear to be querying suspicious domains — a false positive.
        if packet[DNS].qr == 0:
            query = packet[DNSQR].qname
            dns_query = query.decode(errors="replace").rstrip(".")
            protocol = "DNS"

    if Raw in packet:
        raw_bytes = bytes(packet[Raw].load)
        # Payload is capped at 2048 bytes for several reasons:
        #
        # 1. Memory safety — without a cap, a single 1 MB packet would allocate
        #    a 1 MB Python string. At high packet rates (e.g. 10 000 pps) this
        #    could exhaust RAM in seconds.
        #
        # 2. Matching performance — every content:/pcre: rule is evaluated
        #    against payload_text for each packet. Searching a 64 KB string is
        #    ~32× slower than searching 2 KB; the cost compounds under live load.
        #
        # 3. Signature locality — attack signatures (HTTP methods, SQL injection
        #    parameters, malware headers) almost always appear in the first few
        #    hundred bytes of a payload. Real tools like Suricata use fast_pattern
        #    for the same reason: anchor matching to the earliest meaningful offset.
        #
        # 4. No TCP stream reassembly — this engine processes individual packets,
        #    not full TCP streams. A very large raw payload in one packet is
        #    typically a kernel-reassembled segment (GRO/GSO); the application-
        #    layer content that signatures care about is still near the start.
        if len(raw_bytes) > 2048:
            logger.warning("Payload truncated from %d to 2048 bytes for %s -> %s", len(raw_bytes), ip_layer.src, ip_layer.dst)
        payload_text = raw_bytes[:2048].decode("utf-8", errors="replace")

    http_fields = parse_http_payload(payload_text or "")

    return PacketEvent(
        timestamp=float(packet.time),
        src_ip=str(ip_layer.src),
        dst_ip=str(ip_layer.dst),
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=len(packet),
        tcp_flags=tcp_flags,
        icmp_type=icmp_type,
        dns_query=dns_query,
        payload_text=payload_text,
        http_method=http_fields.get("method") or None,
        http_uri=http_fields.get("uri") or None,
        http_host=http_fields.get("host") or None,
        http_user_agent=http_fields.get("user_agent") or None,
    )
