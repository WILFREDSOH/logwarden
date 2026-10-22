import pytest

from logwarden.errors import LogWardenError
from logwarden.ml import FEATURES, MIN_TRAIN_WINDOWS, build_windows, score_anomalies
from logwarden.models import EventType

pytest.importorskip("sklearn")


def normal_traffic(make_event, hours=40):
    """One user per hour logging in successfully from their own IP."""
    return [
        make_event(h * 3600 + 60, EventType.AUTH_SUCCESS, user=f"u{h % 8}", ip=f"192.0.2.{h % 8}")
        for h in range(hours)
    ]


def test_build_windows_features(make_event):
    events = [
        make_event(0, EventType.AUTH_FAILURE, user="a"),
        make_event(30, EventType.INVALID_USER, user="b"),
        make_event(90, EventType.AUTH_SUCCESS, user="a"),
    ]
    ((key, feats),) = build_windows(events, 60, lambda e: False).items()
    assert key[0] == "203.0.113.7"
    assert set(feats) == set(FEATURES)
    assert feats["n_events"] == 3 and feats["n_failures"] == 2 and feats["n_invalid_user"] == 1
    assert feats["n_users"] == 2 and feats["mean_gap_s"] == 45
    assert feats["failure_ratio"] == pytest.approx(2 / 3)


def test_obvious_burst_is_flagged_and_explained(cfg, make_event, failures):
    baseline = normal_traffic(make_event)
    target = normal_traffic(make_event)[:10] + failures(30, gap=20, start=5 * 3600 + 120)
    rows = score_anomalies(target, baseline, cfg)
    top = rows[0]
    assert top["src_ip"] == "203.0.113.7" and top["is_anomaly"]
    assert "n_failures" in [name for name, _, _ in top["top_features"]]
    assert sum(r["is_anomaly"] for r in rows) == 1


def test_scores_are_deterministic(cfg, make_event, failures):
    baseline = normal_traffic(make_event)
    target = failures(10, gap=30)
    assert score_anomalies(target, baseline, cfg) == score_anomalies(target, baseline, cfg)


def test_not_enough_training_data(cfg, make_event):
    with pytest.raises(LogWardenError) as err:
        score_anomalies(normal_traffic(make_event, 5), normal_traffic(make_event, 5), cfg)
    assert err.value.key == "error.ml_not_enough_data"
    assert err.value.params["needed"] == MIN_TRAIN_WINDOWS


def test_self_calibration_without_baseline(cfg, make_event):
    rows = score_anomalies(normal_traffic(make_event), None, cfg)
    assert len(rows) == 40
