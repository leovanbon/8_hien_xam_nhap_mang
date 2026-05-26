from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

from flask import Flask, render_template

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nids.storage import AlertStore


ALERTS_PATH = ROOT / "data" / "alerts.jsonl"

app = Flask(__name__)


@app.route("/")
def index():
    alerts = AlertStore(ALERTS_PATH).read_all()
    alerts_by_type = Counter(alert["attack_type"] for alert in alerts)
    top_sources = Counter(alert.get("source_ip") or "unknown" for alert in alerts)
    severity_counts = Counter(alert["severity"] for alert in alerts)

    return render_template(
        "index.html",
        alerts=list(reversed(alerts[-100:])),
        total_alerts=len(alerts),
        alerts_by_type=alerts_by_type,
        top_sources=top_sources.most_common(5),
        severity_counts=severity_counts,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
