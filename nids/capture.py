from __future__ import annotations

from collections.abc import Callable, Iterator

from .models import PacketEvent
from .parser import packet_to_event


PacketCallback = Callable[[PacketEvent], None]


def read_pcap(path: str) -> Iterator[PacketEvent]:
    try:
        from scapy.all import PcapReader
    except ImportError as exc:
        raise RuntimeError("Install Scapy to read PCAP files: pip install scapy") from exc

    with PcapReader(path) as packets:
        for packet in packets:
            event = packet_to_event(packet)
            if event is not None:
                yield event


def sniff_live(interface: str, callback: PacketCallback, limit: int = 0) -> None:
    try:
        from scapy.all import sniff
    except ImportError as exc:
        raise RuntimeError("Install Scapy for live capture: pip install scapy") from exc

    def handle_packet(packet: object) -> None:
        event = packet_to_event(packet)
        if event is not None:
            callback(event)

    sniff(iface=interface, prn=handle_packet, store=False, count=limit)
