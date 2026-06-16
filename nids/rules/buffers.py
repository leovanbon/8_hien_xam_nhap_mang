from __future__ import annotations

from nids.http_utils import parse_http_payload
from nids.models import PacketEvent


class EventBuffers:
    def __init__(self, event: PacketEvent) -> None:
        self.event = event
        self._http = parse_http_payload(event.payload_text or "")

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
