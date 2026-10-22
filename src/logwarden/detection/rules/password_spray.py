"""LW-002 - Password spraying: one source IP fails on many different accounts."""

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


class PasswordSprayRule(Rule):
    rule_id = "LW-002"

    def evaluate(self, events: Sequence[Event], prior_alerts: Sequence[Alert] = ()) -> list[Alert]:
        needed = self.params["distinct_users"]
        window = timedelta(minutes=self.params["window_minutes"])
        alerts = []
        failures = (e for e in events if e.event_type.is_failure)
        for ip, ip_events in group_by_ip(failures).items():
            bursts = episodes(ip_events, window, lambda win: len(distinct_users(win)) >= needed)
            for burst in bursts:
                users = distinct_users(burst)
                alerts.append(
                    self.make_alert(
                        burst,
                        username=None,
                        src_ip=ip,
                        explanation={
                            "ip": ip,
                            "n_users": len(users),
                            "count": len(burst),
                            "duration": minutes(burst[-1].timestamp - burst[0].timestamp),
                            "threshold": needed,
                            "window": self.params["window_minutes"],
                            "users": listed(users),
                        },
                        score_kwargs={"usernames": users, "count": len(users), "threshold": needed},
                    )
                )
        return alerts
