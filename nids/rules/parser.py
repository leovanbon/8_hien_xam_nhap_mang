from __future__ import annotations

import re
from dataclasses import replace
from typing import Iterable

from .config import Signature
from .models import STICKY_BUFFERS, ContentMatch, PcreMatch, RuleHeader, SuricataRule, Threshold


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
