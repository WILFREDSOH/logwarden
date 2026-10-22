from logwarden.detection.rules.brute_force import BruteForceRule
from logwarden.models import EventType, Severity


def rule(cfg, **params):
    return BruteForceRule({**cfg["rules"]["LW-001"], **params}, cfg["scoring"])


def test_threshold_reached(cfg, failures):
    alerts = rule(cfg).evaluate(failures(5, gap=30))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "LW-001"
    assert (alert.username, alert.src_ip, len(alert.event_ids)) == ("alice", "203.0.113.7", 5)
    assert alert.score == 40 and alert.severity is Severity.MEDIUM
    assert alert.explanation_params["count"] == 5


def test_below_threshold(cfg, failures):
    assert rule(cfg).evaluate(failures(4, gap=10)) == []


def test_window_boundary_is_inclusive(cfg, failures):
    assert len(rule(cfg).evaluate(failures(5, gap=75))) == 1  # 4 x 75 s = exactly 5 min
    assert rule(cfg).evaluate(failures(5, gap=76)) == []  # 304 s > 5 min


def test_successes_are_not_failures(cfg, make_event):
    events = [make_event(i, EventType.AUTH_SUCCESS) for i in range(10)]
    assert rule(cfg).evaluate(events) == []


def test_invalid_user_attempts_count_as_failures(cfg, make_event):
    events = [make_event(i, EventType.INVALID_USER, user=f"u{i}") for i in range(5)]
    alert = rule(cfg).evaluate(events)[0]
    assert alert.username is None  # several accounts targeted
    assert alert.explanation_params["users"] == ["u0", "u1", "u2", "u3", "u4"]


def test_failures_from_different_ips_are_not_combined(cfg, failures):
    events = failures(3, gap=5, ip="203.0.113.1") + failures(3, gap=5, ip="203.0.113.2")
    assert rule(cfg).evaluate(sorted(events, key=lambda e: e.timestamp)) == []


def test_one_alert_per_burst_with_volume_bonus(cfg, failures):
    alerts = rule(cfg).evaluate(failures(40, gap=5))
    assert len(alerts) == 1
    assert len(alerts[0].event_ids) == 40
    assert alerts[0].score == 40 + 15  # 40 >= 8 x 5: three volume steps of +5


def test_two_separate_bursts_give_two_alerts(cfg, failures):
    events = failures(6, gap=10) + failures(6, gap=10, start=3600)
    assert len(rule(cfg).evaluate(events)) == 2


def test_privileged_account_bonus(cfg, failures):
    alert = rule(cfg).evaluate(failures(5, gap=10, user="root"))[0]
    assert alert.score == 55
    assert [i.label_key for i in alert.score_breakdown] == ["score.base", "score.privileged"]


def test_parameters_are_configurable(cfg, failures):
    assert len(rule(cfg, threshold=3).evaluate(failures(3, gap=10))) == 1
    assert rule(cfg, window_minutes=1).evaluate(failures(5, gap=20)) == []


def test_alert_id_is_deterministic(cfg, failures):
    events = failures(5, gap=10)
    assert rule(cfg).evaluate(events)[0].alert_id == rule(cfg).evaluate(events)[0].alert_id
