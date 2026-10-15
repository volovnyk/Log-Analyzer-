"""Categorize system log events and produce text and CSV security reports."""

from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable, Sequence


AUTH_FAILURE_RE = re.compile(
    r"\b(?:failed\s+(?:password|login|authentication)|"
    r"authentication\s+failure|login\s+failed|invalid\s+user|"
    r"too\s+many\s+authentication\s+failures)\b|\b4625\b",
    re.IGNORECASE,
)
SECURITY_RE = re.compile(
    r"\b(?:auth(?:entication|orization)?|login|logon|sudo|"
    r"firewall|permission denied|access denied|security|"
    r"privilege|invalid user|account locked)\b",
    re.IGNORECASE,
)
ERROR_RE = re.compile(
    r"\b(?:error|failed|failure|fatal|exception|panic|critical)\b",
    re.IGNORECASE,
)
WARNING_RE = re.compile(r"\b(?:warn(?:ing)?|deprecated|retrying)\b", re.IGNORECASE)
NETWORK_RE = re.compile(
    r"\b(?:connect(?:ion)?|disconnect(?:ed|ion)?|listen(?:ing)?|"
    r"network|socket|tcp|udp|dns|http\s+\d{3})\b",
    re.IGNORECASE,
)
INFO_RE = re.compile(r"\b(?:info(?:rmation)?|started|stopped|ready)\b", re.IGNORECASE)
SUSPICIOUS_RULES = (
    (
        re.compile(
            r"\b(?:brute[- ]force|credential stuffing|unauthorized access|"
            r"privilege escalation|malware detected|ransomware|"
            r"mimikatz|meterpreter)\b",
            re.IGNORECASE,
        ),
        "Known suspicious activity indicator",
    ),
    (
        re.compile(
            r"\b(?:powershell(?:\.exe)?\s+.{0,40}-(?:enc|encodedcommand)\b|"
            r"base64\s+(?:--decode|-d)\b|curl\b.{0,80}\|\s*(?:sh|bash)\b|"
            r"wget\b.{0,80}\|\s*(?:sh|bash)\b)",
            re.IGNORECASE,
        ),
        "Potentially obfuscated or remotely piped command",
    ),
)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER_RE = re.compile(
    r"\b(?:invalid\s+user|user(?:name)?|account)\s*(?:[=:]\s*|\s+)"
    r"['\"]?([a-z0-9_.@-]+)",
    re.IGNORECASE,
)
HOST_RE = re.compile(r"\bfrom\s+([a-z0-9_.-]+)", re.IGNORECASE)


@dataclass
class LogEvent:
    """One categorized log line."""

    source: str
    line_number: int
    category: str
    severity: str
    message: str
    suspicious: bool = False
    reasons: list[str] = field(default_factory=list)
    auth_failure_key: str | None = None


def _classify(message: str) -> tuple[str, str]:
    if AUTH_FAILURE_RE.search(message) or any(
        pattern.search(message) for pattern, _ in SUSPICIOUS_RULES
    ):
        return "security", "high"
    if SECURITY_RE.search(message):
        return "security", "medium"
    if ERROR_RE.search(message):
        return "error", "high"
    if WARNING_RE.search(message):
        return "warning", "medium"
    if NETWORK_RE.search(message):
        return "network", "low"
    if INFO_RE.search(message):
        return "info", "low"
    return "other", "unknown"


def _auth_failure_key(message: str, source: str, line_number: int) -> str:
    ip_match = IP_RE.search(message)
    if ip_match:
        return f"host:{ip_match.group(0).lower()}"
    user_match = USER_RE.search(message)
    if user_match:
        return f"user:{user_match.group(1).lower()}"
    host_match = HOST_RE.search(message)
    if host_match:
        return f"host:{host_match.group(1).lower()}"
    return f"line:{source}:{line_number}"


def _read_events(paths: Iterable[str | Path]) -> list[LogEvent]:
    events: list[LogEvent] = []
    for input_path in paths:
        path = Path(input_path)
        with path.open("r", encoding="utf-8", errors="replace") as log_file:
            for line_number, raw_line in enumerate(log_file, start=1):
                message = raw_line.rstrip("\r\n")
                if not message.strip():
                    continue

                category, severity = _classify(message)
                event = LogEvent(
                    source=str(path),
                    line_number=line_number,
                    category=category,
                    severity=severity,
                    message=message,
                )
                if AUTH_FAILURE_RE.search(message):
                    event.auth_failure_key = _auth_failure_key(
                        message, str(path), line_number
                    )
                for pattern, reason in SUSPICIOUS_RULES:
                    if pattern.search(message):
                        event.suspicious = True
                        event.reasons.append(reason)
                events.append(event)
    return events


def analyze_logs(
    paths: Iterable[str | Path], failed_login_threshold: int = 5
) -> list[LogEvent]:
    """Analyze log files and mark repeated failed logins as suspicious."""
    if failed_login_threshold < 1:
        raise ValueError("failed_login_threshold must be at least 1")

    events = _read_events(paths)
    failures = Counter(
        event.auth_failure_key
        for event in events
        if event.auth_failure_key is not None
    )
    for event in events:
        key = event.auth_failure_key
        if key is not None and failures[key] >= failed_login_threshold:
            event.suspicious = True
            reason = (
                f"Repeated authentication failures for {key.removeprefix('host:').removeprefix('user:')} "
                f"({failures[key]} attempts)"
            )
            if reason not in event.reasons:
                event.reasons.append(reason)
    return events


def render_text_report(events: Sequence[LogEvent]) -> str:
    """Format analysis results as a readable plain-text report."""
    generated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    categories = Counter(event.category for event in events)
    suspicious = [event for event in events if event.suspicious]
    lines = [
        "Log Analysis Report",
        f"Generated: {generated}",
        f"Events analyzed: {len(events)}",
        f"Suspicious events: {len(suspicious)}",
        "",
        "Events by category:",
    ]
    if categories:
        lines.extend(f"  {category}: {count}" for category, count in sorted(categories.items()))
    else:
        lines.append("  (none)")
    lines.extend(["", "Suspicious activity:"])
    if suspicious:
        for event in suspicious:
            reason = "; ".join(event.reasons)
            lines.append(
                f"  {event.source}:{event.line_number} [{event.severity}] "
                f"{reason}\n    {event.message}"
            )
    else:
        lines.append("  No suspicious activity detected.")
    return "\n".join(lines) + "\n"


def write_csv_report(events: Sequence[LogEvent], output_path: str | Path) -> None:
    """Write every analyzed event to a CSV report."""
    columns = (
        "source",
        "line_number",
        "category",
        "severity",
        "suspicious",
        "reasons",
        "message",
    )
    with Path(output_path).open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=columns)
        writer.writeheader()
        for event in events:
            writer.writerow(
                {
                    "source": event.source,
                    "line_number": event.line_number,
                    "category": event.category,
                    "severity": event.severity,
                    "suspicious": event.suspicious,
                    "reasons": "; ".join(event.reasons),
                    "message": event.message,
                }
            )


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Categorize system logs and export security analysis reports."
    )
    parser.add_argument("logs", nargs="+", help="one or more log files to analyze")
    parser.add_argument(
        "--text-report",
        default="log_analysis_report.txt",
        help="text report path (default: %(default)s)",
    )
    parser.add_argument(
        "--csv-report",
        default="log_analysis_report.csv",
        help="CSV report path (default: %(default)s)",
    )
    parser.add_argument(
        "--failed-login-threshold",
        type=_positive_integer,
        default=5,
        metavar="N",
        help="failed attempts from one host/account required for detection (default: %(default)s)",
    )
    args = parser.parse_args(argv)

    input_paths = [Path(path).resolve() for path in args.logs]
    report_paths = [Path(args.text_report).resolve(), Path(args.csv_report).resolve()]
    if report_paths[0] == report_paths[1]:
        parser.error("text and CSV report paths must be different")
    if set(input_paths).intersection(report_paths):
        parser.error("report paths must not overwrite an input log")

    try:
        events = analyze_logs(args.logs, args.failed_login_threshold)
        report = render_text_report(events)
        Path(args.text_report).write_text(report, encoding="utf-8")
        write_csv_report(events, args.csv_report)
    except OSError as error:
        parser.error(str(error))

    print(report, end="")
    print(f"Text report written to: {Path(args.text_report).resolve()}")
    print(f"CSV report written to: {Path(args.csv_report).resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
