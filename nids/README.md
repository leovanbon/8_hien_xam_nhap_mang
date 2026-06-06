# NIDS Core Modules

This directory contains the packet normalization, detection, and alert storage
code. Read this when you want to understand how one packet becomes zero or more
alerts.

## Module Responsibilities

- `models.py`
  - Defines `PacketEvent`, the normalized packet representation used by rules.
  - Defines `Alert`, the alert representation written to JSONL and displayed in
    the dashboard.
- `parser.py`
  - Converts Scapy packets into `PacketEvent` objects.
  - Extracts IPs, ports, protocol, TCP flags, DNS query names, payload text, and
    lightweight HTTP request fields.
- `capture.py`
  - Provides `read_pcap(path)` for offline PCAP analysis.
  - Provides `sniff_live(interface, callback, limit)` for live capture.
- `engine.py`
  - Owns the high-level `NIDSEngine`.
  - Counts packets and protocols.
  - Runs rules and writes alerts through `AlertStore`.
- `rules.py`
  - Contains the behavior detectors.
  - Contains the Suricata-style rule parser and matcher.
  - Keeps the legacy `Signature` dataclass compatible with older code.
- `storage.py`
  - Appends alerts to newline-delimited JSON.
  - Reads all stored alerts for the dashboard.

## Data Model

`PacketEvent` is intentionally simple. It stores the fields that this project can
currently inspect:

- `timestamp`
- `src_ip`
- `dst_ip`
- `src_port`
- `dst_port`
- `protocol`
- `length`
- `tcp_flags`
- `dns_query`
- `payload_text`
- `http_method`
- `http_uri`
- `http_host`
- `http_user_agent`

Rules should inspect `PacketEvent` fields or use the buffer abstraction in
`EventBuffers` rather than parsing Scapy packets directly. That keeps capture,
parsing, and detection separate.

## Detection Flow

`NIDSEngine.process_event(event)` is the main call path:

1. Increment packet and protocol counters.
2. Call `SlidingWindowRules.evaluate(event)`.
3. Append returned alerts to storage.
4. Update total alert count.
5. Return alerts to the caller for console printing or tests.

`SlidingWindowRules.evaluate(event)` runs:

1. Port scan detector.
2. ICMP flood detector.
3. SYN flood detector.
4. Suspicious DNS domain detector.
5. DNS tunneling suspicion detector.
6. Suricata-style signature engine.

The behavior detectors use sliding windows keyed by source IP. They suppress
repeat alerts for the same source/rule for five seconds.

Current behavior rules:

- `RULE-001` Port Scan
- `RULE-002` ICMP Ping Flood
- `RULE-003` TCP SYN Flood
- `RULE-004` Suspicious DNS Query
- `RULE-005` DNS Tunneling Suspicion

The DNS tunneling detector marks a query suspicious when it sees long query
names, long labels, or high-entropy labels, then alerts after enough suspicious
queries from the same source appear within the configured window.

## Suricata-Style Parser

`SuricataRuleParser.parse(rule_text)` parses one rule. `parse_many()` parses an
iterable of rule strings and ignores empty/comment-only lines.

The parser separates rules into:

- `RuleHeader`: action, protocol, addresses, ports, and direction.
- `ContentMatch`: sticky buffer, pattern, negation, `nocase`, and
  `fast_pattern`.
- `PcreMatch`: sticky buffer, regex, flags, and negation.
- `Threshold`: `track`, `count`, `seconds`, and threshold type.
- `SuricataRule`: final parsed rule object used by the matcher.

Example rule:

```text
alert http any any -> any 80 (msg:"Admin path"; http.uri; content:"/admin"; nocase; sid:910001; rev:1;)
```

The sticky buffer applies to following `content` and `pcre` options until another
sticky buffer changes it. In the example, `content:"/admin"` is matched against
`http.uri`.

## Matcher Behavior

`SuricataRuleEngine.evaluate(event)` does this for each rule:

1. Check action, protocol, source/destination addresses, ports, and direction.
2. Check simple `flow` hints.
3. Match ordered `content` options.
4. Match `pcre` options.
5. Apply `threshold` or `detection_filter`, if present.
6. Create an `Alert`.

Ordered content matching means a later positive `content` must appear after the
previous positive match in the same buffer. This is simpler than Suricata's full
relative keyword model, but it gives predictable rule behavior.

## Adding A New Suricata-Style Rule

For most use cases, add rule text through `RuleConfig`:

```python
from nids.rules import RuleConfig, SlidingWindowRules

rules = SlidingWindowRules(
    RuleConfig(
        suricata_rules=(
            'alert dns any any -> any 53 (msg:"Suspicious DNS"; '
            'dns.query; content:"bad.example"; nocase; sid:910002; rev:1;)',
        )
    )
)
```

Built-in signature defaults are intentionally empty. To load signatures, pass
Suricata-style rule strings through `RuleConfig.suricata_rules`.

## Adding A New Behavior Detector

Add the state container in `SlidingWindowRules.__init__`, call the detector from
`evaluate()`, and return alerts with `_alert_once()`.

Use this pattern:

```python
custom_alert = self._detect_custom_behavior(event)
if custom_alert:
    alerts.append(custom_alert)
```

Keep evidence structured as a dictionary so the dashboard and JSONL output remain
machine-readable.

## Testing Rule Changes

Add focused unit tests in `tests/test_rules.py`. Prefer building `PacketEvent`
objects directly rather than relying on live packets. Tests should cover:

- A matching event.
- A non-matching event when the header, buffer, or threshold should block.
- Alert metadata such as `rule_id`, severity, and `attack_type`.

Run:

```bash
python3 -m unittest discover -s tests
```

## Current Limitations

- No TCP stream reassembly.
- No full Suricata variable expansion.
- No complete Suricata keyword support.
- `fast_pattern` is recorded but not used for accelerated matching.
- HTTP parsing is intentionally lightweight and request-focused.
- DNS parsing stores only the query name exposed by Scapy.
