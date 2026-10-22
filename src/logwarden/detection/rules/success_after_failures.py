"""LW-003 - Successful login preceded by repeated failures from the same source IP.

Counting failures per source IP (any account) covers both "brute force then
success" on one account and "spray then success" on one of the sprayed accounts.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence
from datetime import timedelta

from logwarden.detection.base import Rule, group_by_ip
from logwarden.models import Alert, Event, EventType


class SuccessAfterFailuresRule(Rule):
    rule_id = "LW-003"

    def evaluate(self, events: Sequence[Event], prior_alerts: Sequence[Alert] = ()) -> list[Alert]:
        needed = self.params["failures"]
        window = timedelta(minutes=self.params["window_minutes"])
        alerts = []
        for ip, ip_events in group_by_ip(events).items():
            last_alert_at: dict[str | None, Event] = {}
            recent: deque[Event] = deque()  # failures from this IP within the window
            for event in ip_events:
                while recent and event.timestamp - recent[0].timestamp > window:
                    recent.popleft()
                if event.event_type.is_failure:
                    recent.append(event)
                    continue
                if event.event_type is not EventType.AUTH_SUCCESS:
                    continue
                previous = last_alert_at.get(event.username)
                if previous and event.timestamp - previous.timestamp <= window:
                    continue  # same compromise already reported for this user/IP
                failures = list(recent)
                if len(failures) < needed:
                    continue
                last_alert_at[event.username] = event
                on_same_user = sum(1 for e in failures if e.username == event.username)
                alerts.append(
                    self.make_alert(
                        [*failures, event],
                        username=event.username,
                        src_ip=ip,
                        explanation={
                            "user": event.username or "?",
                            "ip": ip,
                            "failures": len(failures),
                            "same_user": on_same_user,
                            "window": self.params["window_minutes"],
                            "time": event.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                        },
                        score_kwargs={
                            "usernames": [event.username],
                            "count": len(failures),
                            "threshold": needed,
                        },
                    )
                )
        return alerts
