from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest

from logwarden.config import load_config
from logwarden.models import Event, EventType

T0 = datetime(2026, 10, 14, 10, 0, 0, tzinfo=UTC)  # a Wednesday, inside business hours


@pytest.fixture
def cfg() -> dict:
    return load_config()


@pytest.fixture
def make_event() -> Callable[..., Event]:
    """Build an Event `seconds` after T0 (unique raw text so ids never collide)."""
    counter = iter(range(1_000_000))

    def _make(
        seconds: float = 0,
        kind: EventType = EventType.AUTH_FAILURE,
        user: str | None = "alice",
        ip: str = "203.0.113.7",
        source: str = "ssh",
        at: datetime | None = None,
    ) -> Event:
        ts = at or T0 + timedelta(seconds=seconds)
        raw = f"test-{next(counter)} {kind} {user} {ip}"
        return Event(Event.make_id(source, ts, raw), ts, source, kind, user, ip, "host", raw)

    return _make


@pytest.fixture
def failures(make_event) -> Callable[..., list[Event]]:
    """`n` failed logins, one every `gap` seconds, starting `start` seconds after T0."""

    def _failures(n: int, gap: float, start: float = 0, **kw) -> list[Event]:
        return [make_event(start + i * gap, EventType.AUTH_FAILURE, **kw) for i in range(n)]

    return _failures
