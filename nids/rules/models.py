from __future__ import annotations

from dataclasses import dataclass


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
