"""Summary statistics computed from the stored events and alerts (pure Python)."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from logwarden.models import Alert, Event, EventType, Severity
from logwarden.storage import IngestionRun


@dataclass
class Summary:
    events_total: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    by_source: dict[str, int] = field(default_factory=dict)
    unique_ips: int = 0
    unique_users: int = 0
    first_event: datetime | None = None
    last_event: datetime | None = None
    alerts_total: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_rule: dict[str, int] = field(default_factory=dict)
    top_failure_ips: list[tuple[str, int]] = field(default_factory=list)
    top_targeted_users: list[tuple[str, int]] = field(default_factory=list)
    hourly: dict[datetime, dict[str, int]] = field(default_factory=dict)
    lines_total: int = 0
    lines_skipped: int = 0
    duplicates: int = 0
    malformed: dict[str, int] = field(default_factory=dict)
    files: list[str] = field(default_factory=list)


def summarize(
    events: list[Event], alerts: list[Alert], runs: list[IngestionRun], top: int = 10
) -> Summary:
    s = Summary(events_total=len(events), alerts_total=len(alerts))
    s.by_type = {t.value: sum(1 for e in events if e.event_type is t) for t in EventType}
    s.by_source = dict(sorted(Counter(e.source for e in events).items()))
    s.unique_ips = len({e.src_ip for e in events if e.src_ip})
    s.unique_users = len({e.username for e in events if e.username})
    if events:
        s.first_event = min(e.timestamp for e in events)
        s.last_event = max(e.timestamp for e in events)

    s.by_severity = {sev.value: sum(1 for a in alerts if a.severity is sev) for sev in Severity}
    s.by_rule = dict(sorted(Counter(a.rule_id for a in alerts).items()))

    failures = [e for e in events if e.event_type.is_failure]
    s.top_failure_ips = Counter(e.src_ip for e in failures if e.src_ip).most_common(top)
    s.top_targeted_users = Counter(e.username for e in failures if e.username).most_common(top)

    for e in events:
        hour = e.timestamp.replace(minute=0, second=0, microsecond=0)
        bucket = s.hourly.setdefault(hour, {"failures": 0, "successes": 0})
        bucket["failures" if e.event_type.is_failure else "successes"] += 1
    s.hourly = dict(sorted(s.hourly.items()))

    malformed: Counter[str] = Counter()
    for run in runs:
        s.lines_total += run.total_lines
        s.lines_skipped += run.skipped
        s.duplicates += run.duplicates
        malformed.update(run.malformed_detail)
        if run.path not in s.files:
            s.files.append(run.path)
    s.malformed = dict(sorted(malformed.items()))
    return s
