from __future__ import annotations

from collections import Counter

from .models import Alert, PacketEvent
from .rules import RuleConfig, SlidingWindowRules
from .storage import AlertStore


class NIDSEngine:
    def __init__(
        self,
        *,
        rules: SlidingWindowRules | None = None,
        store: AlertStore | None = None,
    ) -> None:
        self.rules = rules or SlidingWindowRules(RuleConfig())
        self.store = store or AlertStore()
        self.packet_count = 0
        self.alert_count = 0
        self.protocol_counts: Counter[str] = Counter()

    def process_event(self, event: PacketEvent) -> list[Alert]:
        self.packet_count += 1
        self.protocol_counts[event.protocol] += 1

        alerts = self.rules.evaluate(event)
        self.store.append_many(alerts)
        self.alert_count += len(alerts)
        return alerts

    def summary(self) -> dict:
        return {
            "packet_count": self.packet_count,
            "alert_count": self.alert_count,
            "protocol_counts": dict(self.protocol_counts),
        }
