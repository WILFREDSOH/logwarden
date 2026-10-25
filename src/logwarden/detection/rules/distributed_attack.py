"""LW-006 - Distributed attack: many different source IPs fail on the same account.

Rules LW-001 and LW-002 group events by source IP, so an attacker who spreads
attempts over many addresses (a botnet) stays under their thresholds. This
rule groups failures by *targeted account* instead.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from datetime import timedelta

from logwarden.detection.base import Rule, episodes, listed, minutes
from logwarden.models import Alert, Event


class DistributedAttackRule(Rule):
    rule_id = "LW-006"

    def evaluate(self, events: Sequence[Event], prior_alerts: Sequence[Alert] = ()) -> list[Alert]:
        needed = self.params["distinct_ips"]
        window = timedelta(minutes=self.params["window_minutes"])

        by_user: dict[str, list[Event]] = defaultdict(list)
        for event in events:
            if event.event_type.is_failure and event.username:
                by_user[event.username].append(event)

        alerts = []
        for user, user_events in sorted(by_user.items()):
            bursts = episodes(
                user_events, window, lambda win: len({e.src_ip for e in win}) >= needed
            )
            for burst in bursts:
                ips = sorted({e.src_ip for e in burst if e.src_ip})
                alerts.append(
                    self.make_alert(
                        burst,
                        username=user,
                        src_ip=None,
                        explanation={
                            "user": user,
                            "n_ips": len(ips),
                            "count": len(burst),
                            "duration": minutes(burst[-1].timestamp - burst[0].timestamp),
                            "threshold": needed,
                            "window": self.params["window_minutes"],
                            "ips": listed(ips),
                        },
                        score_kwargs={"usernames": [user], "count": len(ips), "threshold": needed},
                    )
                )
        return alerts
