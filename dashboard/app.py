from __future__ import annotations

import os
import sys
import time
import shutil
from datetime import datetime
from collections import Counter
from pathlib import Path

from flask import Flask, render_template, request, jsonify, cli
import logging

# Suppress the "This is a development server" warning
cli.show_server_banner = lambda *args: None
logging.getLogger("werkzeug").setLevel(logging.ERROR)
logging.getLogger("werkzeug").disabled = True

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nids.storage import AlertStore


ALERTS_PATH = ROOT / "data" / "alerts.jsonl"

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Cache: re-read the JSONL file only when its mtime changes
# ---------------------------------------------------------------------------
_cache: dict = {"mtime": 0.0, "alerts": []}


def _get_alerts() -> list[dict]:
    """Return cached alerts, refreshing only when the file has been modified."""
    try:
        current_mtime = ALERTS_PATH.stat().st_mtime
    except FileNotFoundError:
        _cache["mtime"] = 0.0
        _cache["alerts"] = []
        return []

    if current_mtime != _cache["mtime"]:
        _cache["alerts"] = AlertStore(ALERTS_PATH).read_all()
        _cache["mtime"] = current_mtime

    return _cache["alerts"]


def _paginate(items: list, page: int, per_page: int) -> tuple[list, int, int, int]:
    """Return (page_items, total, total_pages, current_page)."""
    total = len(items)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    end = start + per_page
    return items[start:end], total, total_pages, page


def _build_alert_data(alerts: list[dict]) -> dict:
    """Build computed statistics from alert list."""
    alerts_by_type = Counter(a["attack_type"] for a in alerts)
    top_sources = Counter(a.get("source_ip") or "unknown" for a in alerts)
    severity_counts = Counter(a["severity"] for a in alerts)
    return {
        "alerts_by_type": alerts_by_type,
        "top_sources": top_sources.most_common(5),
        "severity_counts": severity_counts,
    }


@app.route("/")
def index():
    all_alerts = _get_alerts()
    # Show latest alerts first (reversed)
    recent = list(reversed(all_alerts))

    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 100, type=int)
    per_page = max(1, min(per_page, 500))  # clamp

    page_alerts, total, total_pages, page = _paginate(recent, page, per_page)
    stats = _build_alert_data(all_alerts)

    return render_template(
        "index.html",
        alerts=page_alerts,
        total_alerts=len(all_alerts),
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        **stats,
    )


@app.route("/api/alerts")
def api_alerts():
    all_alerts = _get_alerts()
    recent = list(reversed(all_alerts))

    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 100, type=int)
    per_page = max(1, min(per_page, 500))

    page_alerts, total, total_pages, page = _paginate(recent, page, per_page)
    stats = _build_alert_data(all_alerts)

    return jsonify({
        "alerts": page_alerts,
        "total_alerts": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "alerts_by_type": dict(stats["alerts_by_type"]),
        "top_sources": stats["top_sources"],
        "severity_counts": dict(stats["severity_counts"]),
    })


@app.route("/api/alerts/clear", methods=["POST"])
def api_clear_alerts():
    if ALERTS_PATH.exists():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        saved_path = ALERTS_PATH.with_name(f"alerts_saved_{timestamp}.jsonl")
        shutil.move(str(ALERTS_PATH), str(saved_path))
    
    ALERTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with ALERTS_PATH.open("w"):
        pass

    global _cache
    _cache["mtime"] = 0.0
    _cache["alerts"] = []

    return jsonify({"status": "success"})


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )
