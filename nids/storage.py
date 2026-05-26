from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .models import Alert


class AlertStore:
    def __init__(self, path: str | Path = "data/alerts.jsonl") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, alert: Alert) -> None:
        with self.path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(alert.to_dict(), sort_keys=True) + "\n")

    def append_many(self, alerts: Iterable[Alert]) -> None:
        for alert in alerts:
            self.append(alert)

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []

        alerts: list[dict] = []
        with self.path.open("r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if line:
                    alerts.append(json.loads(line))
        return alerts
