"""LW-004 - Successful login outside business hours (or on a weekend).

Successes of the same user from the same IP on the same local day are grouped
into one alert. Service accounts listed in `exempt_users` are ignored.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from datetime import date
from typing import Any

from logwarden.detection.base import Rule, listed
from logwarden.ingestion import get_timezone
from logwarden.models import Alert, Event, EventType


class OffHoursRule(Rule):
    rule_id = "LW-004"

    def __init__(self, params: dict[str, Any], scoring: dict[str, Any]) -> None:
        super().__init__(params, scoring)
        self.tz = get_timezone(params["timezone"])  # fail early on an unknown zone

    def is_off_hours(self, event: Event) -> bool:
        local = event.timestamp.astimezone(self.tz)
        if self.params["weekends_are_off_hours"] and local.weekday() >= 5:
            return True
        return (
            not self.params["business_start_hour"] <= local.hour < self.params["business_end_hour"]
        )

    def evaluate(self, events: Sequence[Event], prior_alerts: Sequence[Alert] = ()) -> list[Alert]:
        tz = self.tz
        exempt = {u.lower() for u in self.params["exempt_users"]}
        groups: dict[tuple[str | None, str | None, date], list[Event]] = defaultdict(list)
        for event in events:
            if event.event_type is not EventType.AUTH_SUCCESS:
                continue
            if (event.username or "").lower() in exempt or not self.is_off_hours(event):
                continue
            local_day = event.timestamp.astimezone(tz).date()
            groups[(event.username, event.src_ip, local_day)].append(event)

        alerts = []
        for (user, ip, day), group in groups.items():
            times = [e.timestamp.astimezone(tz).strftime("%H:%M") for e in group]
            alerts.append(
                self.make_alert(
                    group,
                    username=user,
                    src_ip=ip,
                    explanation={
                        "user": user or "?",
                        "ip": ip or "?",
                        "day": day.isoformat(),
                        "times": listed(times),
                        "start": self.params["business_start_hour"],
                        "end": self.params["business_end_hour"],
                        "tz": self.params["timezone"],
                    },
                    score_kwargs={"usernames": [user]},
                )
            )
        return alerts
