from __future__ import annotations

import ipaddress
import math
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field, replace
from typing import Iterable

from .models import Alert, PacketEvent


STICKY_BUFFERS = {
    "pkt_data": "payload",
    "raw_data": "payload",
    "dns.query": "dns.query",
    "http.method": "http.method",
    "http.uri": "http.uri",
    "http.request_line": "http.request_line",
    "http.header": "http.header",
    "http.user_agent": "http.user_agent",
    "http.host": "http.host",
}


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


@dataclass(frozen=True)
class RuleHeader:
    action: str
    protocol: str
    src_addr: str
    src_port: str
    direction: str
    dst_addr: str
    dst_port: str


@dataclass(frozen=True)
class ContentMatch:
    buffer: str
    pattern: str
    nocase: bool = False
    negate: bool = False
    fast_pattern: bool = False


@dataclass(frozen=True)
class PcreMatch:
    buffer: str
    expression: str
    flags: str = ""
    negate: bool = False


@dataclass(frozen=True)
class Threshold:
    track: str
    count: int
    seconds: int
    kind: str = "threshold"


@dataclass(frozen=True)
class SuricataRule:
    header: RuleHeader
    msg: str
    sid: str
    rev: str = "1"
    classtype: str = "unknown"
    priority: int | None = None
    contents: tuple[ContentMatch, ...] = ()
    pcres: tuple[PcreMatch, ...] = ()
    flow: tuple[str, ...] = ()
    threshold: Threshold | None = None
    raw: str = ""

    @property
    def rule_id(self) -> str:
        return self.sid

    @property
    def severity(self) -> str:
        if self.priority == 1:
            return "High"
        if self.priority == 2:
            return "Medium"
        if self.priority == 3:
            return "Low"
        return "Informational"


class SuricataRuleParser:
    HEADER_RE = re.compile(
        r"^(?P<action>\S+)\s+"
        r"(?P<proto>\S+)\s+"
        r"(?P<src>\S+)\s+"
        r"(?P<sp>\S+)\s+"
        r"(?P<dir><>|->|<-)\s+"
        r"(?P<dst>\S+)\s+"
        r"(?P<dp>\S+)\s*"
        r"\((?P<opts>.*)\)\s*$"
    )

    @classmethod
    def parse_many(cls, rules: Iterable[str]) -> tuple[SuricataRule, ...]:
        parsed: list[SuricataRule] = []
        for line in rules:
            clean = cls._strip_comment(line).strip()
            if clean:
                parsed.append(cls.parse(clean))
        return tuple(parsed)

    @classmethod
    def parse(cls, rule_text: str) -> SuricataRule:
        match = cls.HEADER_RE.match(rule_text)
        if not match:
            raise ValueError(f"Invalid Suricata rule header: {rule_text}")

        header = RuleHeader(
            action=match.group("action").lower(),
            protocol=match.group("proto").lower(),
            src_addr=match.group("src"),
            src_port=match.group("sp"),
            direction=match.group("dir"),
            dst_addr=match.group("dst"),
            dst_port=match.group("dp"),
        )

        msg = ""
        sid = ""
        rev = "1"
        classtype = "unknown"
        priority: int | None = None
        flow: tuple[str, ...] = ()
        threshold: Threshold | None = None
        current_buffer = "payload"
        contents: list[ContentMatch] = []
        pcres: list[PcreMatch] = []

        for option in cls._split_options(match.group("opts")):
            key, value = cls._split_option(option)
            key = key.lower()
            if key in STICKY_BUFFERS and value is None:
                current_buffer = STICKY_BUFFERS[key]
            elif key == "content" and value is not None:
                negate, pattern = cls._decode_match_value(value)
                contents.append(ContentMatch(current_buffer, pattern, negate=negate))
            elif key == "pcre" and value is not None:
                negate, expression = cls._decode_match_value(value)
                regex, flags = cls._split_pcre(expression)
                pcres.append(PcreMatch(current_buffer, regex, flags, negate))
            elif key == "nocase" and contents:
                contents[-1] = replace(contents[-1], nocase=True)
            elif key == "fast_pattern" and contents:
                contents[-1] = replace(contents[-1], fast_pattern=True)
            elif key == "msg" and value is not None:
                msg = cls._unquote(value)
            elif key == "sid" and value is not None:
                sid = value.strip()
            elif key == "rev" and value is not None:
                rev = value.strip()
            elif key == "classtype" and value is not None:
                classtype = value.strip()
            elif key == "priority" and value is not None:
                priority = int(value.strip())
            elif key == "flow" and value is not None:
                flow = tuple(item.strip().lower() for item in value.split(",") if item.strip())
            elif key in {"threshold", "detection_filter"} and value is not None:
                threshold = cls._parse_threshold(value, key)

        if not sid:
            sid = f"local:{abs(hash(rule_text))}"
        if not msg:
            msg = f"Rule {sid}"

        return SuricataRule(
            header=header,
            msg=msg,
            sid=sid,
            rev=rev,
            classtype=classtype,
            priority=priority,
            contents=tuple(contents),
            pcres=tuple(pcres),
            flow=flow,
            threshold=threshold,
            raw=rule_text,
        )

    @classmethod
    def from_signature(cls, signature: Signature) -> SuricataRule:
        field_to_buffer = {
            "payload_text": "payload",
            "dns_query": "dns.query",
            "http_method": "http.method",
            "http_uri": "http.uri",
            "http_host": "http.host",
            "http_user_agent": "http.user_agent",
        }
        priority = {"High": 1, "Medium": 2, "Low": 3}.get(signature.severity, 4)
        protocol = (signature.protocol or "ip").lower()
        dst_port = str(signature.dst_port) if signature.dst_port is not None else "any"
        content = ContentMatch(
            buffer=field_to_buffer.get(signature.field, signature.field),
            pattern=signature.pattern,
            nocase=not signature.case_sensitive,
        )
        return SuricataRule(
            header=RuleHeader(
                action="alert",
                protocol=protocol,
                src_addr="any",
                src_port="any",
                direction="->",
                dst_addr="any",
                dst_port=dst_port,
            ),
            msg=signature.attack_type,
            sid=signature.rule_id,
            priority=priority,
            contents=(content,),
            raw=f"legacy signature {signature.rule_id}",
        )

    @staticmethod
    def _strip_comment(line: str) -> str:
        in_quote = False
        escaped = False
        for index, char in enumerate(line):
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_quote = not in_quote
            elif char == "#" and not in_quote:
                return line[:index]
        return line

    @staticmethod
    def _split_options(options: str) -> list[str]:
        parts: list[str] = []
        start = 0
        in_quote = False
        escaped = False
        for index, char in enumerate(options):
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_quote = not in_quote
            elif char == ";" and not in_quote:
                part = options[start:index].strip()
                if part:
                    parts.append(part)
                start = index + 1
        tail = options[start:].strip()
        if tail:
            parts.append(tail)
        return parts

    @staticmethod
    def _split_option(option: str) -> tuple[str, str | None]:
        in_quote = False
        escaped = False
        for index, char in enumerate(option):
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_quote = not in_quote
            elif char == ":" and not in_quote:
                return option[:index].strip(), option[index + 1 :].strip()
        return option.strip(), None

    @classmethod
    def _decode_match_value(cls, value: str) -> tuple[bool, str]:
        negate = value.startswith("!")
        if negate:
            value = value[1:].strip()
        return negate, cls._decode_content(cls._unquote(value))

    @staticmethod
    def _unquote(value: str) -> str:
        value = value.strip()
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        return (
            value.replace(r"\"", '"')
            .replace(r"\;", ";")
            .replace(r"\:", ":")
            .replace(r"\\", "\\")
        )

    @staticmethod
    def _decode_content(value: str) -> str:
        def replace_hex(match: re.Match[str]) -> str:
            bytes_out = bytearray()
            for item in match.group(1).split():
                bytes_out.append(int(item, 16))
            return bytes(bytes_out).decode("latin1")

        return re.sub(r"\|([0-9A-Fa-f ]+)\|", replace_hex, value)

    @staticmethod
    def _split_pcre(expression: str) -> tuple[str, str]:
        if len(expression) >= 2 and expression[0] == "/":
            end = expression.rfind("/")
            if end > 0:
                return expression[1:end], expression[end + 1 :]
        return expression, ""

    @staticmethod
    def _parse_threshold(value: str, kind: str) -> Threshold:
        parts: dict[str, str] = {}
        for item in value.split(","):
            item = item.strip()
            if not item:
                continue
            if " " in item:
                key, val = item.split(None, 1)
                parts[key.lower()] = val.strip()
        return Threshold(
            track=parts.get("track", "by_src"),
            count=int(parts.get("count", "1")),
            seconds=int(parts.get("seconds", "1")),
            kind=parts.get("type", kind),
        )


class SuricataRuleEngine:
    def __init__(self, rules: Iterable[SuricataRule]) -> None:
        self.rules = tuple(rules)
        self._threshold_windows: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    @classmethod
    def from_config(cls, config: RuleConfig) -> "SuricataRuleEngine":
        parsed = list(SuricataRuleParser.parse_many(config.suricata_rules))
        parsed.extend(SuricataRuleParser.from_signature(sig) for sig in config.signatures)
        return cls(parsed)

    def evaluate(self, event: PacketEvent) -> list[Alert]:
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

    def _header_matches(
        self, header: RuleHeader, event: PacketEvent, buffers: "EventBuffers"
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
    def _protocol_matches(protocol: str, event: PacketEvent, buffers: "EventBuffers") -> bool:
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
    def _content_matches(rule: SuricataRule, buffers: "EventBuffers") -> bool:
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
    def _pcre_matches(rule: SuricataRule, buffers: "EventBuffers") -> bool:
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


class EventBuffers:
    def __init__(self, event: PacketEvent) -> None:
        self.event = event
        self._http = self._parse_http(event.payload_text or "")

    @property
    def is_http(self) -> bool:
        return bool(self._http["request_line"])

    def get(self, name: str) -> str:
        if name == "payload":
            return self.event.payload_text or ""
        if name == "dns.query":
            return self.event.dns_query or ""
        if name == "http.method":
            return self._field_or_http("http_method", "method")
        if name == "http.uri":
            return self._field_or_http("http_uri", "uri")
        if name == "http.request_line":
            return self._http["request_line"]
        if name == "http.header":
            return self._http["header"]
        if name == "http.host":
            return self._field_or_http("http_host", "host")
        if name == "http.user_agent":
            return self._field_or_http("http_user_agent", "user_agent")
        return str(getattr(self.event, name, "") or "")

    def _field_or_http(self, attr: str, key: str) -> str:
        return str(getattr(self.event, attr, None) or self._http[key] or "")

    @staticmethod
    def _parse_http(payload: str) -> dict[str, str]:
        if not payload:
            return {"request_line": "", "method": "", "uri": "", "header": "", "host": "", "user_agent": ""}
        lines = payload.splitlines()
        request_line = lines[0] if lines else ""
        parts = request_line.split()
        method = parts[0] if len(parts) >= 2 and parts[0].isalpha() else ""
        uri = parts[1] if method else ""
        header = "\n".join(lines[1:])
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line.strip():
                break
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        return {
            "request_line": request_line if method else "",
            "method": method,
            "uri": uri,
            "header": header,
            "host": headers.get("host", ""),
            "user_agent": headers.get("user-agent", ""),
        }


class SlidingWindowRules:
    def __init__(self, config: RuleConfig | None = None) -> None:
        self.config = config or RuleConfig()
        self.suricata = SuricataRuleEngine.from_config(self.config)
        self._dest_ports_by_src: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._icmp_by_src: dict[str, deque[float]] = defaultdict(deque)
        self._syn_by_src: dict[str, deque[float]] = defaultdict(deque)
        self._dns_tunnel_by_src: dict[str, deque[tuple[float, str, tuple[str, ...]]]] = (
            defaultdict(deque)
        )
        self._recent_alert_keys: dict[tuple[str, str], float] = {}
        self._cooldown_seconds = 5

    def evaluate(self, event: PacketEvent) -> list[Alert]:
        alerts: list[Alert] = []
        if not event.src_ip:
            return alerts

        port_scan_alert = self._detect_port_scan(event)
        if port_scan_alert:
            alerts.append(port_scan_alert)

        icmp_alert = self._detect_icmp_flood(event)
        if icmp_alert:
            alerts.append(icmp_alert)

        syn_alert = self._detect_syn_flood(event)
        if syn_alert:
            alerts.append(syn_alert)

        dns_alert = self._detect_suspicious_dns(event)
        if dns_alert:
            alerts.append(dns_alert)

        dns_tunnel_alert = self._detect_dns_tunneling(event)
        if dns_tunnel_alert:
            alerts.append(dns_tunnel_alert)

        alerts.extend(self.suricata.evaluate(event))

        return alerts

    def _detect_port_scan(self, event: PacketEvent) -> Alert | None:
        if event.protocol != "TCP" or event.dst_port is None:
            return None

        window = self._dest_ports_by_src[event.src_ip or ""]
        window.append((event.timestamp, event.dst_port))
        self._drop_old_ports(window, event.timestamp, self.config.port_scan_window_seconds)

        unique_ports = {port for _, port in window}
        if len(unique_ports) < self.config.port_scan_unique_ports:
            return None

        return self._alert_once(
            now=event.timestamp,
            rule_id="RULE-001",
            key=event.src_ip or "unknown",
            attack_type="Port Scan",
            severity="Medium",
            source_ip=event.src_ip,
            destination_ip=event.dst_ip,
            description=(
                f"{event.src_ip} contacted {len(unique_ports)} unique TCP ports "
                f"in {self.config.port_scan_window_seconds} seconds"
            ),
            evidence={"unique_ports": sorted(unique_ports), "count": len(unique_ports)},
        )

    def _detect_icmp_flood(self, event: PacketEvent) -> Alert | None:
        if event.protocol != "ICMP":
            return None

        window = self._icmp_by_src[event.src_ip or ""]
        window.append(event.timestamp)
        self._drop_old_times(window, event.timestamp, self.config.icmp_flood_window_seconds)

        if len(window) < self.config.icmp_flood_packet_count:
            return None

        return self._alert_once(
            now=event.timestamp,
            rule_id="RULE-002",
            key=event.src_ip or "unknown",
            attack_type="ICMP Ping Flood",
            severity="High",
            source_ip=event.src_ip,
            destination_ip=event.dst_ip,
            description=(
                f"{event.src_ip} sent {len(window)} ICMP packets "
                f"in {self.config.icmp_flood_window_seconds} seconds"
            ),
            evidence={"icmp_packets": len(window)},
        )

    def _detect_syn_flood(self, event: PacketEvent) -> Alert | None:
        if event.protocol != "TCP" or event.tcp_flags != "S":
            return None

        window = self._syn_by_src[event.src_ip or ""]
        window.append(event.timestamp)
        self._drop_old_times(window, event.timestamp, self.config.syn_flood_window_seconds)

        if len(window) < self.config.syn_flood_syn_count:
            return None

        return self._alert_once(
            now=event.timestamp,
            rule_id="RULE-003",
            key=event.src_ip or "unknown",
            attack_type="TCP SYN Flood",
            severity="High",
            source_ip=event.src_ip,
            destination_ip=event.dst_ip,
            description=(
                f"{event.src_ip} sent {len(window)} SYN packets "
                f"in {self.config.syn_flood_window_seconds} seconds"
            ),
            evidence={"syn_packets": len(window)},
        )

    def _detect_suspicious_dns(self, event: PacketEvent) -> Alert | None:
        if not event.dns_query:
            return None

        query = event.dns_query.lower()
        suspicious_match = next(
            (
                domain
                for domain in self.config.suspicious_domains
                if query == domain or query.endswith(f".{domain}")
            ),
            None,
        )
        if not suspicious_match:
            return None

        return self._alert_once(
            now=event.timestamp,
            rule_id="RULE-004",
            key=f"{event.src_ip}:{query}",
            attack_type="Suspicious DNS Query",
            severity="Medium",
            source_ip=event.src_ip,
            destination_ip=event.dst_ip,
            description=f"{event.src_ip} queried suspicious domain {query}",
            evidence={"query": query, "matched_domain": suspicious_match},
        )

    def _detect_dns_tunneling(self, event: PacketEvent) -> Alert | None:
        if not event.dns_query:
            return None

        query = event.dns_query.lower().rstrip(".")
        reasons = self._dns_tunnel_reasons(query)
        if not reasons:
            return None

        window = self._dns_tunnel_by_src[event.src_ip or ""]
        window.append((event.timestamp, query, tuple(reasons)))
        while window and event.timestamp - window[0][0] > self.config.dns_tunnel_window_seconds:
            window.popleft()

        if len(window) < self.config.dns_tunnel_suspicious_count:
            return None

        recent_queries = [entry[1] for entry in window]
        reason_counts: dict[str, int] = defaultdict(int)
        for _, _, entry_reasons in window:
            for reason in entry_reasons:
                reason_counts[reason] += 1

        return self._alert_once(
            now=event.timestamp,
            rule_id="RULE-005",
            key=event.src_ip or "unknown",
            attack_type="DNS Tunneling Suspicion",
            severity="Medium",
            source_ip=event.src_ip,
            destination_ip=event.dst_ip,
            description=(
                f"{event.src_ip} sent {len(window)} DNS queries with tunneling "
                f"indicators in {self.config.dns_tunnel_window_seconds} seconds"
            ),
            evidence={
                "suspicious_queries": len(window),
                "recent_queries": recent_queries[-5:],
                "reason_counts": dict(reason_counts),
                "latest_query": query,
            },
        )

    def _dns_tunnel_reasons(self, query: str) -> list[str]:
        reasons: list[str] = []
        labels = [label for label in query.split(".") if label]
        longest_label = max((len(label) for label in labels), default=0)
        highest_entropy = max((self._shannon_entropy(label) for label in labels), default=0.0)

        if len(query) >= self.config.dns_tunnel_min_query_length:
            reasons.append("long_query_name")
        if longest_label >= self.config.dns_tunnel_min_label_length:
            reasons.append("long_label")
        if (
            longest_label >= self.config.dns_tunnel_entropy_label_length
            and highest_entropy >= self.config.dns_tunnel_min_label_entropy
        ):
            reasons.append("high_entropy_label")

        return reasons

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        counts: dict[str, int] = defaultdict(int)
        for char in value:
            counts[char] += 1
        length = len(value)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    def _alert_once(
        self,
        *,
        now: float,
        rule_id: str,
        key: str,
        attack_type: str,
        severity: str,
        source_ip: str | None,
        destination_ip: str | None,
        description: str,
        evidence: dict,
    ) -> Alert | None:
        alert_key = (rule_id, key)
        last_alert = self._recent_alert_keys.get(alert_key)
        if last_alert is not None and now - last_alert < self._cooldown_seconds:
            return None

        self._recent_alert_keys[alert_key] = now
        return Alert.create(
            rule_id=rule_id,
            attack_type=attack_type,
            severity=severity,
            source_ip=source_ip,
            destination_ip=destination_ip,
            description=description,
            evidence=evidence,
        )

    @staticmethod
    def _drop_old_ports(window: deque[tuple[float, int]], now: float, seconds: int) -> None:
        while window and now - window[0][0] > seconds:
            window.popleft()

    @staticmethod
    def _drop_old_times(window: deque[float], now: float, seconds: int) -> None:
        while window and now - window[0] > seconds:
            window.popleft()
