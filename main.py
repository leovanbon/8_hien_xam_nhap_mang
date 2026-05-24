from __future__ import annotations

import argparse
from pathlib import Path

from nids.capture import read_pcap, sniff_live
from nids.engine import NIDSEngine
from nids.storage import AlertStore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Simple rule-based NIDS")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pcap", help="Path to a PCAP file to analyze")
    source.add_argument("--iface", help="Network interface for live capture")
    parser.add_argument("--limit", type=int, default=0, help="Live packet capture limit")
    parser.add_argument(
        "--alerts",
        default="data/alerts.jsonl",
        help="Path where alerts are written as JSONL",
    )
    return parser


def print_alerts(alerts: list) -> None:
    for alert in alerts:
        print(
            f"[{alert.severity}] {alert.attack_type}: "
            f"{alert.description} ({alert.rule_id})"
        )


def main() -> int:
    args = build_parser().parse_args()
    engine = NIDSEngine(store=AlertStore(args.alerts))

    if args.pcap:
        pcap_path = Path(args.pcap)
        if not pcap_path.exists():
            print(f"PCAP not found: {pcap_path}")
            return 2

        for event in read_pcap(str(pcap_path)):
            print_alerts(engine.process_event(event))
    else:
        def on_event(event) -> None:
            print_alerts(engine.process_event(event))

        sniff_live(args.iface, on_event, limit=args.limit)

    summary = engine.summary()
    print("\nSummary")
    print(f"Packets processed: {summary['packet_count']}")
    print(f"Alerts generated: {summary['alert_count']}")
    print(f"Protocol counts: {summary['protocol_counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
