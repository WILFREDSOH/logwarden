from logwarden.detection.rules.password_spray import PasswordSprayRule
from logwarden.models import EventType


def rule(cfg, **params):
    return PasswordSprayRule({**cfg["rules"]["LW-002"], **params}, cfg["scoring"])


def spray(make_event, users, gap=30, **kw):
    return [make_event(i * gap, EventType.AUTH_FAILURE, user=u, **kw) for i, u in enumerate(users)]


def test_four_accounts_within_window(cfg, make_event):
    alerts = rule(cfg).evaluate(spray(make_event, ["a", "b", "c", "d"]))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.username is None
    assert alert.explanation_params["n_users"] == 4
    assert alert.score == 55


def test_three_accounts_is_not_enough(cfg, make_event):
    assert rule(cfg).evaluate(spray(make_event, ["a", "b", "c"])) == []


def test_many_failures_on_one_account_is_not_spraying(cfg, make_event):
    assert rule(cfg).evaluate(spray(make_event, ["alice"] * 20, gap=5)) == []


def test_accounts_spread_beyond_window(cfg, make_event):
    # 4 accounts but each 4 minutes apart: never 4 distinct ones within 10 minutes.
    assert rule(cfg).evaluate(spray(make_event, ["a", "b", "c", "d"], gap=240)) == []


def test_privileged_target_and_volume(cfg, make_event):
    users = ["root"] + [f"u{i}" for i in range(15)]  # 16 accounts = 4x the threshold
    alert = rule(cfg).evaluate(spray(make_event, users, gap=10))[0]
    assert alert.score == 55 + 15 + 10
    assert alert.explanation_params["users"][-1] == "(+6)"  # list capped at 10 + marker


def test_events_without_username_are_ignored(cfg, make_event):
    assert rule(cfg).evaluate(spray(make_event, [None, None, None, None, "a"])) == []
