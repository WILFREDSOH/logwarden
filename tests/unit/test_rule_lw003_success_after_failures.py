from logwarden.detection.rules.success_after_failures import SuccessAfterFailuresRule
from logwarden.models import EventType, Severity


def rule(cfg, **params):
    return SuccessAfterFailuresRule({**cfg["rules"]["LW-003"], **params}, cfg["scoring"])


def test_success_after_three_failures(cfg, failures, make_event):
    events = [*failures(3, gap=20), make_event(70, EventType.AUTH_SUCCESS)]
    alerts = rule(cfg).evaluate(events)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.username == "alice"
    assert len(alert.event_ids) == 4
    assert alert.score == 70 and alert.severity is Severity.HIGH
    assert alert.explanation_params["same_user"] == 3


def test_two_typos_then_success_is_normal(cfg, failures, make_event):
    events = [*failures(2, gap=10), make_event(30, EventType.AUTH_SUCCESS)]
    assert rule(cfg).evaluate(events) == []


def test_failures_outside_window_are_ignored(cfg, failures, make_event):
    events = [*failures(5, gap=10), make_event(11 * 60 + 50, EventType.AUTH_SUCCESS)]
    assert rule(cfg).evaluate(events) == []


def test_failures_from_another_ip_do_not_count(cfg, failures, make_event):
    events = [*failures(5, gap=10, ip="203.0.113.99"), make_event(60, EventType.AUTH_SUCCESS)]
    assert rule(cfg).evaluate(events) == []


def test_spray_then_success_on_another_account(cfg, make_event):
    events = [make_event(i * 10, EventType.AUTH_FAILURE, user=u) for i, u in enumerate("abcd")]
    events.append(make_event(50, EventType.AUTH_SUCCESS, user="carol"))
    alert = rule(cfg).evaluate(events)[0]
    assert alert.explanation_params["failures"] == 4
    assert alert.explanation_params["same_user"] == 0


def test_repeated_success_reported_once(cfg, failures, make_event):
    events = [
        *failures(3, gap=10),
        make_event(40, EventType.AUTH_SUCCESS),
        make_event(100, EventType.AUTH_SUCCESS),
    ]
    assert len(rule(cfg).evaluate(events)) == 1


def test_privileged_account_is_critical(cfg, failures, make_event):
    events = [
        *failures(6, gap=10, user="admin"),
        make_event(70, EventType.AUTH_SUCCESS, user="admin"),
    ]
    alert = rule(cfg).evaluate(events)[0]
    assert alert.score == 70 + 15 + 5  # 6 failures = 2x the threshold
    assert alert.severity is Severity.CRITICAL
