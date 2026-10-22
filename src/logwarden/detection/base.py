"""Common building blocks for detection rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import defaultdict, deque
from collections.abc import Callable, Iterable, Sequence
from datetime import timedelta
from typing import Any, ClassVar

from logwarden.detection.scoring import compute_score
from logwarden.models import Alert, Event

MAX_LISTED = 10  # cap list parameters (users, times) shown in explanations


class Rule(ABC):
    """A detection rule turns a time-ordered list of events into alerts.

    Rules are pure functions of (events, parameters): no I/O, no global state,
    which makes each of them testable on a handful of hand-written events.
    """

    rule_id: ClassVar[str]
    #: correlation rules run after the others and receive their alerts
    correlation: ClassVar[bool] = False

    def __init__(self, params: dict[str, Any], scoring: dict[str, Any]) -> None:
        self.params = params
        self.scoring = scoring

    @abstractmethod
    def evaluate(self, events: Sequence[Event], prior_alerts: Sequence[Alert] = ()) -> list[Alert]:
        """`events` must be sorted by timestamp."""

    def make_alert(
        self,
        events: Sequence[Event],
        *,
        username: str | None,
        src_ip: str | None,
        explanation: dict[str, Any],
        score_kwargs: dict[str, Any],
        discriminator: str = "",
    ) -> Alert:
        score, severity, breakdown = compute_score(
            self.params["base_score"], self.scoring, **score_kwargs
        )
        event_ids = tuple(e.event_id for e in events)
        return Alert(
            alert_id=Alert.make_id(self.rule_id, event_ids, discriminator),
            rule_id=self.rule_id,
            severity=severity,
            score=score,
            first_seen=min(e.timestamp for e in events),
            last_seen=max(e.timestamp for e in events),
            username=username,
            src_ip=src_ip,
            event_ids=event_ids,
            explanation_key=f"explain.{self.rule_id}",
            explanation_params=explanation,
            score_breakdown=breakdown,
        )


def group_by_ip(events: Iterable[Event]) -> dict[str, list[Event]]:
    groups: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.src_ip:
            groups[event.src_ip].append(event)
    return dict(sorted(groups.items()))


def episodes(
    events: Sequence[Event],
    window: timedelta,
    trigger: Callable[[Sequence[Event]], bool],
) -> list[list[Event]]:
    """Find bursts of activity that satisfy `trigger` within a sliding window.

    A sliding window holds the events of the last `window`. As soon as
    `trigger(window_events)` is true an *episode* starts with those events, and
    it keeps absorbing new events as long as each one arrives less than `window`
    after the previous one. This yields one alert per attack burst instead of
    one alert per event.
    """
    found: list[list[Event]] = []
    win: deque[Event] = deque()
    current: list[Event] | None = None
    for event in events:
        if current is not None:
            if event.timestamp - current[-1].timestamp <= window:
                current.append(event)
                continue
            found.append(current)
            current = None
            win.clear()
        win.append(event)
        while event.timestamp - win[0].timestamp > window:
            win.popleft()
        if trigger(win):
            current = list(win)
    if current is not None:
        found.append(current)
    return found


def distinct_users(events: Iterable[Event]) -> list[str]:
    return sorted({e.username for e in events if e.username})


def listed(values: Sequence[str]) -> list[str]:
    """Cap a list shown in an explanation, saying how many items were left out."""
    if len(values) <= MAX_LISTED:
        return list(values)
    return [*values[:MAX_LISTED], f"(+{len(values) - MAX_LISTED})"]


def minutes(delta: timedelta) -> float:
    return round(delta.total_seconds() / 60, 1)
