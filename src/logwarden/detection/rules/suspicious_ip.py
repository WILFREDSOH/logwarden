"""LW-005 - Suspicious source IP across the whole dataset (correlation rule).

An IP is flagged when it triggered at least `min_distinct_rules` different rules,
or when it tried at least `invalid_user_threshold` non-existent accounts
(typical of automated scanners using username dictionaries).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from logwarden.detection.base import Rule, distinct_users, group_by_ip, listed
from logwarden.models import Alert, Event, EventType


class SuspiciousIpRule(Rule):
    rule_id = "LW-005"
    correlation = True

    def evaluate(self, events: Sequence[Event], prior_alerts: Sequence[Alert] = ()) -> list[Alert]:
        rules_by_ip: dict[str, set[str]] = defaultdict(set)
        for alert in prior_alerts:
            if alert.src_ip and alert.rule_id != self.rule_id:
                rules_by_ip[alert.src_ip].add(alert.rule_id)

        alerts = []
        for ip, ip_events in group_by_ip(events).items():
            rules = sorted(rules_by_ip.get(ip, ()))
            invalid = [e for e in ip_events if e.event_type is EventType.INVALID_USER]
            by_rules = len(rules) >= self.params["min_distinct_rules"]
            by_invalid = len(invalid) >= self.params["invalid_user_threshold"]
            if not (by_rules or by_invalid):
                continue
            successes = [e for e in ip_events if e.event_type is EventType.AUTH_SUCCESS]
            failures = [e for e in ip_events if e.event_type.is_failure]
            evidence = sorted([*failures, *successes], key=lambda e: e.timestamp)
            users = distinct_users(evidence)
            alerts.append(
                self.make_alert(
                    evidence,
                    username=None,
                    src_ip=ip,
                    explanation={
                        "ip": ip,
                        "rules": rules or ["-"],
                        "invalid": len(invalid),
                        "invalid_users": listed(distinct_users(invalid)) or ["-"],
                        "failures": len(failures),
                        "successes": len(successes),
                        "success_users": listed(distinct_users(successes)) or ["-"],
                    },
                    score_kwargs={
                        "usernames": users,
                        "success": bool(successes),
                        "count": len(invalid),
                        "threshold": self.params["invalid_user_threshold"],
                    },
                    discriminator=ip,
                )
            )
        return alerts
