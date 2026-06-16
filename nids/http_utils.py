from __future__ import annotations


def parse_http_payload(payload: str) -> dict[str, str]:
    """Parse HTTP request payload and extract method, URI, headers, etc.

    Returns a dict with keys: request_line, method, uri, header, host, user_agent.
    All values are strings (empty string when not found).
    """
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
