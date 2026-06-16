from __future__ import annotations

import ipaddress
import re
from collections import defaultdict, deque
from typing import Iterable

from nids.models import Alert, PacketEvent

from .config import RuleConfig
from .models import ContentMatch, PcreMatch, RuleHeader, SuricataRule, Threshold
from .parser import SuricataRuleParser
from .buffers import EventBuffers


class SuricataRuleEngine:
    def __init__(self, rules: Iterable[SuricataRule]) -> None:
        self.rules = tuple(rules)
        self._threshold_windows: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._eval_count: int = 0

    @classmethod
    def from_config(cls, config: RuleConfig) -> "SuricataRuleEngine":
        parsed = list(SuricataRuleParser.parse_many(config.suricata_rules))
        parsed.extend(SuricataRuleParser.from_signature(sig) for sig in config.signatures)
        return cls(parsed)

    def evaluate(self, event: PacketEvent) -> list[Alert]:
        self._eval_count += 1
        if self._eval_count % 1000 == 0:
            self._cleanup_threshold_windows()

        alerts: list[Alert] = []
        buffers = EventBuffers(event)
        for rule in self.rules:
            if not self._header_matches(rule.header, event, buffers):
                continue
            if not self._flow_matches(rule, event):
                continue
            if not self._content_matches(rule, buffers):
                continue
            if not self._pcre_matches(rule, buffers):
                continue
            if not self._threshold_allows(rule, event):
                continue
            alerts.append(self._make_alert(rule, event))
        return alerts

    def _cleanup_threshold_windows(self) -> None:
        """Remove entries with empty deques from threshold windows."""
        empty_keys = [k for k, v in self._threshold_windows.items() if not v]
        for k in empty_keys:
            del self._threshold_windows[k]

    def _header_matches(
        self, header: RuleHeader, event: PacketEvent, buffers: EventBuffers
    ) -> bool:
        if header.action != "alert":
            return False
        if not self._protocol_matches(header.protocol, event, buffers):
            return False
        forward = (
            self._addr_matches(header.src_addr, event.src_ip)
            and self._port_matches(header.src_port, event.src_port)
            and self._addr_matches(header.dst_addr, event.dst_ip)
            and self._port_matches(header.dst_port, event.dst_port)
        )
        if header.direction == "->":
            return forward
        reverse = (
            self._addr_matches(header.src_addr, event.dst_ip)
            and self._port_matches(header.src_port, event.dst_port)
            and self._addr_matches(header.dst_addr, event.src_ip)
            and self._port_matches(header.dst_port, event.src_port)
        )
        if header.direction == "<>":
            return forward or reverse
        return reverse

    @staticmethod
    def _protocol_matches(protocol: str, event: PacketEvent, buffers: EventBuffers) -> bool:
        event_protocol = event.protocol.lower()
        if protocol in {"ip", "any"}:
            return True
        if protocol in {"tcp", "udp", "icmp", "dns"}:
            return event_protocol == protocol or (
                protocol == "dns" and (event.src_port == 53 or event.dst_port == 53)
            )
        if protocol in {"http", "http1", "http2"}:
            return event_protocol == "http" or buffers.is_http
        if protocol == "tcp-pkt":
            return event_protocol == "tcp"
        return event_protocol == protocol

    @staticmethod
    def _addr_matches(expr: str, ip_value: str | None) -> bool:
        expr = expr.strip()
        negate = expr.startswith("!")
        if negate:
            expr = expr[1:].strip()
        if expr in {"any", "$HOME_NET", "$EXTERNAL_NET"}:
            return not negate
        if expr.startswith("[") and expr.endswith("]"):
            matched = any(SuricataRuleEngine._addr_matches(part.strip(), ip_value) for part in expr[1:-1].split(","))
            return not matched if negate else matched
        if ip_value is None:
            return negate
        try:
            ip_obj = ipaddress.ip_address(ip_value)
            if "/" in expr:
                matched = ip_obj in ipaddress.ip_network(expr, strict=False)
            else:
                matched = ip_obj == ipaddress.ip_address(expr)
        except ValueError:
            matched = False
        return not matched if negate else matched

    @staticmethod
    def _port_matches(expr: str, port: int | None) -> bool:
        expr = expr.strip()
        negate = expr.startswith("!")
        if negate:
            expr = expr[1:].strip()
        if expr in {"any", "$HTTP_PORTS"}:
            return not negate
        if expr.startswith("[") and expr.endswith("]"):
            matched = any(SuricataRuleEngine._port_matches(part.strip(), port) for part in expr[1:-1].split(","))
            return not matched if negate else matched
        if port is None:
            return negate
        if ":" in expr:
            lower, upper = expr.split(":", 1)
            min_port = int(lower) if lower else 0
            max_port = int(upper) if upper else 65535
            matched = min_port <= port <= max_port
        else:
            try:
                matched = port == int(expr)
            except ValueError:
                matched = False
        return not matched if negate else matched

    @staticmethod
    def _flow_matches(rule: SuricataRule, event: PacketEvent) -> bool:
        if not rule.flow:
            return True
        flags = set(rule.flow)
        if "to_server" in flags and event.dst_port is None:
            return False
        if "to_client" in flags and event.src_port is None:
            return False
        return True

    @staticmethod
    def _content_matches(rule: SuricataRule, buffers: EventBuffers) -> bool:
        positions: dict[str, int] = defaultdict(int)
        for content in rule.contents:
            haystack = buffers.get(content.buffer)
            needle = content.pattern
            if content.nocase:
                haystack = haystack.lower()
                needle = needle.lower()
            index = haystack.find(needle, positions[content.buffer])
            matched = index >= 0
            if content.negate and matched:
                return False
            if not content.negate and not matched:
                return False
            if matched:
                positions[content.buffer] = index + len(needle)
        return True

    @staticmethod
    def _pcre_matches(rule: SuricataRule, buffers: EventBuffers) -> bool:
        for pcre in rule.pcres:
            flags = 0
            if "i" in pcre.flags:
                flags |= re.IGNORECASE
            matched = re.search(pcre.expression, buffers.get(pcre.buffer), flags) is not None
            if pcre.negate and matched:
                return False
            if not pcre.negate and not matched:
                return False
        return True

    def _threshold_allows(self, rule: SuricataRule, event: PacketEvent) -> bool:
        if rule.threshold is None:
            return True
        track_key = self._threshold_track_key(rule.threshold.track, event)
        window = self._threshold_windows[(rule.sid, track_key)]
        window.append(event.timestamp)
        while window and event.timestamp - window[0] > rule.threshold.seconds:
            window.popleft()
        return len(window) >= rule.threshold.count

    @staticmethod
    def _threshold_track_key(track: str, event: PacketEvent) -> str:
        if track == "by_dst":
            return event.dst_ip or "unknown"
        if track == "by_rule":
            return "rule"
        return event.src_ip or "unknown"

    @staticmethod
    def _make_alert(rule: SuricataRule, event: PacketEvent) -> Alert:
        return Alert.create(
            rule_id=rule.rule_id,
            attack_type=rule.msg,
            severity=rule.severity,
            source_ip=event.src_ip,
            destination_ip=event.dst_ip,
            description=f"{event.src_ip} matched Suricata rule {rule.rule_id}: {rule.msg}",
            evidence={
                "action": rule.header.action,
                "protocol": rule.header.protocol,
                "sid": rule.sid,
                "rev": rule.rev,
                "classtype": rule.classtype,
                "contents": [
                    {
                        "buffer": content.buffer,
                        "pattern": content.pattern,
                        "nocase": content.nocase,
                        "fast_pattern": content.fast_pattern,
                    }
                    for content in rule.contents
                ],
            },
        )
