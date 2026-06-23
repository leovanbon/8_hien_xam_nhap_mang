# Dashboard

The dashboard is a small Flask application for viewing alerts written by the
NIDS engine. It reads `data/alerts.jsonl`, calculates summary counters, and
renders a single HTML page.

## Run It

From the project root:

```bash
python3 dashboard/app.py
```

Open:

```text
http://127.0.0.1:5000
```

If there are no alerts yet, generate demo data:

```bash
python3 scripts/demo_events.py
```

## Files

- `app.py`
  - Creates the Flask app.
  - Reads alerts through `nids.storage.AlertStore`.
  - Computes alert type counts, severity counts, and top source IPs.
  - Sends the latest 100 alerts to the template.
- `templates/index.html`
  - Renders summary metric cards and the recent alert table.
- `static/style.css`
  - Contains dashboard styles.

## Data Source

The dashboard currently reads:

```text
data/alerts.jsonl
```

Each line must be one JSON object shaped like `nids.models.Alert.to_dict()`.
The most important fields are:

- `timestamp`
- `rule_id`
- `attack_type`
- `detection_method`
- `severity`
- `source_ip`
- `destination_ip`
- `description`
- `evidence`

The CLI can write to a different alert path with `--alerts`, but the dashboard
is currently hard-coded to `data/alerts.jsonl` in `dashboard/app.py`.

## Expected Workflow

1. Run packet analysis or demo generation.
2. Alerts are appended to `data/alerts.jsonl`.
3. Start or refresh the dashboard.
4. Review total alert count, alert types, severity distribution, top sources,
   and recent alert rows.

## Development Notes

The dashboard does not auto-refresh, authenticate users, or expose an API. It is
intended as a simple local viewer for a semester project. If you extend it, the
next useful improvements are configurable alert file paths, filtering by
severity/source/type, and live refresh.
