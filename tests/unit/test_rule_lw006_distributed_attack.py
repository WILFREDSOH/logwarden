from logwarden.detection.rules.distributed_attack import DistributedAttackRule
from logwarden.models import EventType, Severity


def rule(cfg, **params):
    return DistributedAttackRule({**cfg["rules"]["LW-006"], **params}, cfg["scoring"])


def from_ips(make_event, n_ips, gap=30, user="alice"):
    """One failed login on `user` from each of `n_ips` different addresses."""
    return [
        make_event(i * gap, EventType.AUTH_FAILURE, user=user, ip=f"203.0.113.{100 + i}")
        for i in range(n_ips)
    ]


def test_four_ips_on_one_account(cfg, make_event):
    alerts = rule(cfg).evaluate(from_ips(make_event, 4))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "LW-006"
    assert alert.username == "alice" and alert.src_ip is None
    assert alert.explanation_params["n_ips"] == 4
    assert alert.score == 55 and alert.severity is Severity.MEDIUM


def test_three_ips_is_not_enough(cfg, make_event):
    assert rule(cfg).evaluate(from_ips(make_event, 3)) == []


def test_one_ip_many_failures_is_not_distributed(cfg, failures):
    assert rule(cfg).evaluate(failures(20, gap=5)) == []  # that is LW-001's job


def test_ips_spread_beyond_window(cfg, make_event):
    # 4 IPs, but 4 minutes apart: never 4 distinct IPs within 10 minutes.
    assert rule(cfg).evaluate(from_ips(make_event, 4, gap=240)) == []


def test_different_accounts_are_not_combined(cfg, make_event):
    events = from_ips(make_event, 2, user="alice") + from_ips(make_event, 2, user="bob")
    assert rule(cfg).evaluate(sorted(events, key=lambda e: e.timestamp)) == []


def test_privileged_account_and_volume(cfg, make_event):
    alert = rule(cfg).evaluate(from_ips(make_event, 8, gap=10, user="root"))[0]
    assert alert.score == 55 + 15 + 5  # privileged, 8 IPs = 2x the threshold
    assert alert.severity is Severity.HIGH


def test_successes_are_ignored(cfg, make_event):
    events = [
        make_event(i * 30, EventType.AUTH_SUCCESS, user="alice", ip=f"192.0.2.{i}")
        for i in range(6)
    ]
    assert rule(cfg).evaluate(events) == []
