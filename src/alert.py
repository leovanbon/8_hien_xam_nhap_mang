import datetime
import json
from dataclasses import asdict, dataclass
from typing import Optional


@dataclass(frozen=True)
class Alert:
    timestamp: float
    severity: str
    category: str
    message: str
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    evidence: Optional[str] = None

    def format_console(self) -> str:
        timestamp = datetime.datetime.fromtimestamp(self.timestamp).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        ports = ""
        if self.src_port is not None or self.dst_port is not None:
            ports = f" {self.src_port or '-'} -> {self.dst_port or '-'}"

        evidence = f" | Evidence: {self.evidence}" if self.evidence else ""
        return (
            f"[{timestamp}] [{self.severity}] {self.category}: {self.message} "
            f"({self.src_ip} -> {self.dst_ip}, {self.protocol}{ports}){evidence}"
        )

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


class AlertLogger:
    def __init__(self, log_path: Optional[str] = None, quiet: bool = False):
        self.log_path = log_path
        self.quiet = quiet

    def emit(self, alert: Alert) -> None:
        if not self.quiet:
            print(alert.format_console())

        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8") as log_file:
                log_file.write(alert.to_json() + "\n")
