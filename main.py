from __future__ import annotations

import argparse
from pathlib import Path

from nids.capture import read_pcap, sniff_live
from nids.engine import NIDSEngine
from nids.rules import RuleConfig, SlidingWindowRules
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
    parser.add_argument(
        "--rules",
        help="Path to a Suricata-style .rules file to load alongside the built-in behavior rules",
    )
    return parser


def load_suricata_rules(path: str) -> tuple[str, ...]:
    """Read a .rules file and return non-empty, non-comment lines as a tuple."""
    rules_path = Path(path)
    if not rules_path.exists():
        print(f"Rules file not found: {rules_path}")
        raise SystemExit(2)
    lines = rules_path.read_text(encoding="utf-8").splitlines()
    return tuple(
        line.strip()
        for line in lines
        if line.strip() and not line.strip().startswith("#")
    )


def print_alerts(alerts: list) -> None:
    for alert in alerts:
        print(
            f"[{alert.severity}] {alert.attack_type}: "
            f"{alert.description} ({alert.rule_id})"
        )


def main() -> int:
    args = build_parser().parse_args()

    suricata_rules: tuple[str, ...] = ()
    if args.rules:
        suricata_rules = load_suricata_rules(args.rules)
        print(f"Loaded {len(suricata_rules)} Suricata rule(s) from {args.rules}")

    config = RuleConfig(suricata_rules=suricata_rules)
    engine = NIDSEngine(rules=SlidingWindowRules(config), store=AlertStore(args.alerts))

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
