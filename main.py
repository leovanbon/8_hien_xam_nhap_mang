import argparse

from src.alert import AlertLogger
from src.detector import RuleBasedDetector


def build_argument_parser():
    parser = argparse.ArgumentParser(
        description="Simple rule-based Network Intrusion Detection System demo."
    )
    parser.add_argument(
        "-i",
        "--interface",
        default=None,
        help="Network interface to sniff. Omit to let Scapy choose.",
    )
    parser.add_argument(
        "-f",
        "--filter",
        default="ip",
        help="BPF capture filter passed to Scapy. Default: ip.",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Stop after this many packets. Default: 0, run until Ctrl+C.",
    )
    parser.add_argument(
        "--log",
        default=None,
        help="Optional JSON Lines file to append alerts to.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Do not print alerts to the terminal.",
    )
    parser.add_argument(
        "--icmp-threshold",
        type=int,
        default=10,
        help="Alert after this many ICMP packets within the ICMP window.",
    )
    parser.add_argument(
        "--icmp-window",
        type=int,
        default=10,
        help="ICMP flood detection window in seconds.",
    )
    parser.add_argument(
        "--port-scan-threshold",
        type=int,
        default=10,
        help="Alert after this many distinct TCP destination ports within the scan window.",
    )
    parser.add_argument(
        "--port-scan-window",
        type=int,
        default=30,
        help="Port scan detection window in seconds.",
    )
    return parser


def main():
    args = build_argument_parser().parse_args()

    from src.parser import PacketParser
    from src.sniffer import NIDSSniffer

    packet_parser = PacketParser()
    detector = RuleBasedDetector(
        icmp_threshold=args.icmp_threshold,
        icmp_window_seconds=args.icmp_window,
        port_scan_threshold=args.port_scan_threshold,
        port_scan_window_seconds=args.port_scan_window,
    )
    alert_logger = AlertLogger(log_path=args.log, quiet=args.quiet)

    def analyze_packet(packet):
        parsed_packet = packet_parser.parse(packet)
        for alert in detector.analyze(parsed_packet):
            alert_logger.emit(alert)

    nids = NIDSSniffer(
        interface=args.interface,
        callback_function=analyze_packet,
        bpf_filter=args.filter,
        packet_count=args.count,
    )
    nids.start()


if __name__ == "__main__":
    main()
