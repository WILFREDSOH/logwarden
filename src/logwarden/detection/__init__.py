"""Detection engine: runs the enabled rules over normalised events."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from logwarden.detection.base import Rule
from logwarden.detection.rules.brute_force import BruteForceRule
from logwarden.detection.rules.off_hours import OffHoursRule
from logwarden.detection.rules.password_spray import PasswordSprayRule
from logwarden.detection.rules.success_after_failures import SuccessAfterFailuresRule
from logwarden.detection.rules.suspicious_ip import SuspiciousIpRule
from logwarden.models import Alert, Event

RULE_CLASSES: tuple[type[Rule], ...] = (
    BruteForceRule,
    PasswordSprayRule,
    SuccessAfterFailuresRule,
    OffHoursRule,
    SuspiciousIpRule,
)
RULE_IDS = tuple(cls.rule_id for cls in RULE_CLASSES)


def build_rules(cfg: dict[str, Any]) -> list[Rule]:
    rules = []
    for cls in RULE_CLASSES:
        params = cfg["rules"][cls.rule_id]
        if params["enabled"]:
            rules.append(cls(params, cfg["scoring"]))
    return rules


def sort_alerts(alerts: Iterable[Alert]) -> list[Alert]:
    """Most urgent first: severity, then score, then time."""
    return sorted(alerts, key=lambda a: (-a.severity.rank, -a.score, a.first_seen, a.alert_id))


def run_detection(events: Iterable[Event], cfg: dict[str, Any]) -> list[Alert]:
    ordered = sorted(events, key=lambda e: (e.timestamp, e.event_id))
    rules = build_rules(cfg)
    alerts: list[Alert] = []
    for rule in (r for r in rules if not r.correlation):
        alerts.extend(rule.evaluate(ordered))
    for rule in (r for r in rules if r.correlation):
        alerts.extend(rule.evaluate(ordered, tuple(alerts)))
    return sort_alerts(alerts)
