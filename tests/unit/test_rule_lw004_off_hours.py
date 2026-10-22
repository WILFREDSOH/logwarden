from datetime import UTC, datetime

import pytest

from logwarden.detection.rules.off_hours import OffHoursRule
from logwarden.models import EventType, Severity


def rule(cfg, **params):
    return OffHoursRule({**cfg["rules"]["LW-004"], **params}, cfg["scoring"])


def at(hour, minute=0, day=14):  # 2026-10-14 is a Wednesday, 17 a Saturday
    return datetime(2026, 10, day, hour, minute, tzinfo=UTC)


@pytest.mark.parametrize(
    ("ts", "expected"),
    [
        (at(3), 1),
        (at(6, 59), 1),
        (at(7, 0), 0),  # start hour is inclusive
        (at(19, 59), 0),
        (at(20, 0), 1),  # end hour is exclusive
        (at(10, day=17), 1),  # Saturday
    ],
)
def test_business_hours_boundaries(cfg, make_event, ts, expected):
    assert len(rule(cfg).evaluate([make_event(kind=EventType.AUTH_SUCCESS, at=ts)])) == expected


def test_weekends_can_be_allowed(cfg, make_event):
    event = make_event(kind=EventType.AUTH_SUCCESS, at=at(10, day=17))
    assert rule(cfg, weekends_are_off_hours=False).evaluate([event]) == []


def test_failures_are_ignored(cfg, make_event):
    assert rule(cfg).evaluate([make_event(kind=EventType.AUTH_FAILURE, at=at(3))]) == []


def test_exempt_service_account(cfg, make_event):
    event = make_event(kind=EventType.AUTH_SUCCESS, user="svc_backup", at=at(2))
    assert rule(cfg).evaluate([event]) == []


def test_business_timezone(cfg, make_event):
    event = make_event(kind=EventType.AUTH_SUCCESS, at=at(6, 30))  # 08:30 in Paris (CEST)
    assert len(rule(cfg).evaluate([event])) == 1
    assert rule(cfg, timezone="Europe/Paris").evaluate([event]) == []


def test_same_user_ip_day_grouped(cfg, make_event):
    events = [make_event(kind=EventType.AUTH_SUCCESS, at=at(h)) for h in (1, 2, 22)]
    alerts = rule(cfg).evaluate(events)
    assert len(alerts) == 1
    assert alerts[0].explanation_params["times"] == ["01:00", "02:00", "22:00"]
    assert alerts[0].severity is Severity.LOW


def test_privileged_account_is_medium(cfg, make_event):
    alert = rule(cfg).evaluate([make_event(kind=EventType.AUTH_SUCCESS, user="root", at=at(3))])[0]
    assert alert.score == 40 and alert.severity is Severity.MEDIUM
