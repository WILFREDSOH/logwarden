from dataclasses import replace

from logwarden.detection.rules.suspicious_ip import SuspiciousIpRule
from logwarden.models import Alert, EventType, Severity


def rule(cfg, **params):
    return SuspiciousIpRule({**cfg["rules"]["LW-005"], **params}, cfg["scoring"])


def fake_alert(rule_id, event, ip="203.0.113.7"):
    return Alert(
        alert_id=rule_id,
        rule_id=rule_id,
        severity=Severity.LOW,
        score=10,
        first_seen=event.timestamp,
        last_seen=event.timestamp,
        username=None,
        src_ip=ip,
        event_ids=(event.event_id,),
        explanation_key="x",
    )


def test_invalid_users_threshold(cfg, make_event):
    events = [make_event(i, EventType.INVALID_USER, user=f"u{i}") for i in range(3)]
    alerts = rule(cfg).evaluate(events, ())
    assert len(alerts) == 1
    assert alerts[0].explanation_params["invalid"] == 3
    assert rule(cfg).evaluate(events[:2], ()) == []


def test_several_distinct_rules(cfg, make_event):
    event = make_event(0)
    prior = [fake_alert("LW-001", event), fake_alert("LW-002", event)]
    alert = rule(cfg).evaluate([event], prior)[0]
    assert alert.explanation_params["rules"] == ["LW-001", "LW-002"]


def test_one_rule_twice_is_not_enough(cfg, make_event):
    event = make_event(0)
    prior = [fake_alert("LW-001", event), replace(fake_alert("LW-001", event), alert_id="b")]
    assert rule(cfg).evaluate([event], prior) == []


def test_alerts_on_other_ips_do_not_count(cfg, make_event):
    event = make_event(0)
    prior = [fake_alert("LW-001", event), fake_alert("LW-002", event, ip="198.51.100.1")]
    assert rule(cfg).evaluate([event], prior) == []


def test_success_from_flagged_ip_raises_score(cfg, make_event):
    events = [make_event(0), make_event(10, EventType.AUTH_SUCCESS)]
    prior = [fake_alert("LW-001", events[0]), fake_alert("LW-003", events[1])]
    alert = rule(cfg).evaluate(events, prior)[0]
    assert alert.score == 50 + 20
    assert alert.explanation_params["success_users"] == ["alice"]
