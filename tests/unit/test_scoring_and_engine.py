import pytest

from logwarden.detection import RULE_IDS, run_detection
from logwarden.detection.scoring import compute_score, severity_for, volume_bonus
from logwarden.models import EventType, Severity


@pytest.mark.parametrize(
    ("score", "severity"),
    [
        (0, Severity.LOW),
        (29, Severity.LOW),
        (30, Severity.MEDIUM),
        (59, Severity.MEDIUM),
        (60, Severity.HIGH),
        (84, Severity.HIGH),
        (85, Severity.CRITICAL),
        (100, Severity.CRITICAL),
    ],
)
def test_severity_bands(score, severity):
    assert severity_for(score) is severity


@pytest.mark.parametrize(
    ("count", "bonus"), [(5, 0), (9, 0), (10, 5), (20, 10), (40, 15), (999, 15)]
)
def test_volume_bonus(cfg, count, bonus):
    assert volume_bonus(count, 5, cfg["scoring"]) == bonus


def test_score_is_capped_and_breakdown_explains_it(cfg):
    score, severity, items = compute_score(
        90, cfg["scoring"], usernames=["Root"], success=True, count=100, threshold=5
    )
    assert score == 100 and severity is Severity.CRITICAL
    assert sum(i.points for i in items) == 100
    assert items[-1].label_key == "score.cap"


def test_engine_runs_all_rules_and_sorts_by_urgency(cfg, failures, make_event):
    events = [
        *failures(6, gap=10, user="root"),
        make_event(70, EventType.AUTH_SUCCESS, user="root"),
    ]
    alerts = run_detection(list(reversed(events)), cfg)  # input order must not matter
    assert {a.rule_id for a in alerts} == {"LW-001", "LW-003", "LW-005"}
    ranks = [(a.severity.rank, a.score) for a in alerts]
    assert ranks == sorted(ranks, reverse=True)


def test_disabled_rule_does_not_run(cfg, failures):
    cfg["rules"]["LW-001"]["enabled"] = False
    assert run_detection(failures(10, gap=5), cfg) == []


def test_no_events_no_alerts(cfg):
    assert run_detection([], cfg) == []


def test_rule_ids_are_unique():
    assert len(set(RULE_IDS)) == len(RULE_IDS) == 6
