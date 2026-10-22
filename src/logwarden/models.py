"""Core data model.

An *Event* is a single normalised fact read from a log ("alice failed to log in
from 203.0.113.5 at 10:02:13"). An *Alert* is a conclusion drawn by a detection
rule from one or more events. Keeping them separate lets us re-run detection
with new parameters without re-reading the logs.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class EventType(StrEnum):
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"  # wrong password for an existing account
    INVALID_USER = "invalid_user"  # attempt against an account that does not exist

    @property
    def is_failure(self) -> bool:
        return self in (EventType.AUTH_FAILURE, EventType.INVALID_USER)


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


@dataclass(frozen=True, slots=True)
class Event:
    event_id: str
    timestamp: datetime  # always timezone-aware, UTC
    source: str  # "ssh" or "webapp"
    event_type: EventType
    username: str | None
    src_ip: str | None
    host: str = ""
    raw: str = ""  # sanitised, truncated original line (for analysts, never executed)

    @staticmethod
    def make_id(source: str, timestamp: datetime, raw: str) -> str:
        """Deterministic id: the same line ingested twice yields the same id (dedup)."""
        digest = hashlib.sha256(f"{source}|{timestamp.isoformat()}|{raw}".encode())
        return digest.hexdigest()[:20]


@dataclass(frozen=True, slots=True)
class ScoreItem:
    label_key: str  # i18n key, e.g. "score.privileged"
    points: int


@dataclass(frozen=True, slots=True)
class Alert:
    alert_id: str
    rule_id: str
    severity: Severity
    score: int
    first_seen: datetime
    last_seen: datetime
    username: str | None
    src_ip: str | None
    event_ids: tuple[str, ...]
    explanation_key: str
    explanation_params: dict = field(default_factory=dict)
    score_breakdown: tuple[ScoreItem, ...] = ()

    @staticmethod
    def make_id(rule_id: str, event_ids: tuple[str, ...], discriminator: str = "") -> str:
        payload = rule_id + "|" + discriminator + "|" + ",".join(sorted(event_ids))
        return hashlib.sha256(payload.encode()).hexdigest()[:20]


def utc(dt: datetime) -> datetime:
    """Return `dt` as an aware UTC datetime (naive values are assumed to be UTC)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)
