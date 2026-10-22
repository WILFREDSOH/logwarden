"""LW-001 - Brute force: many failed logins from one source IP in a short time."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta

from logwarden.detection.base import (
    Rule,
    distinct_users,
    episodes,
    group_by_ip,
    listed,
    minutes,
)
from logwarden.models import Alert, Event


class BruteForceRule(Rule):
    rule_id = "LW-001"

    def evaluate(self, events: Sequence[Event], prior_alerts: Sequence[Alert] = ()) -> list[Alert]:
        threshold = self.params["threshold"]
        window = timedelta(minutes=self.params["window_minutes"])
        alerts = []
        failures = (e for e in events if e.event_type.is_failure)
        for ip, ip_events in group_by_ip(failures).items():
            for burst in episodes(ip_events, window, lambda win: len(win) >= threshold):
                users = distinct_users(burst)
                alerts.append(
                    self.make_alert(
                        burst,
                        username=users[0] if len(users) == 1 else None,
                        src_ip=ip,
                        explanation={
                            "count": len(burst),
                            "ip": ip,
                            "duration": minutes(burst[-1].timestamp - burst[0].timestamp),
                            "threshold": threshold,
                            "window": self.params["window_minutes"],
                            "users": listed(users),
                        },
                        score_kwargs={
                            "usernames": users,
                            "count": len(burst),
                            "threshold": threshold,
                        },
                    )
                )
        return alerts
