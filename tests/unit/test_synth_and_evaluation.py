import ipaddress
from pathlib import Path

from logwarden.evaluation import Confusion, evaluate
from logwarden.synth import GroundTruth, generate

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def test_generation_is_deterministic(tmp_path):
    a, _ = generate(tmp_path / "a", seed=1)
    b, _ = generate(tmp_path / "b", seed=1)
    c, _ = generate(tmp_path / "c", seed=2)
    assert [p.read_bytes() for p in a] == [p.read_bytes() for p in b]
    assert a[0].read_bytes() != c[0].read_bytes()


def test_committed_samples_match_generator(tmp_path):
    """data/samples is the output of `logwarden generate --out data/samples` (seed 42)."""
    paths, _ = generate(tmp_path)
    for path in paths:
        assert path.read_bytes() == (SAMPLES / path.name).read_bytes(), path.name


def test_only_documentation_ip_ranges_are_used(tmp_path):
    paths, gt = generate(tmp_path)
    text = paths[0].read_text() + paths[1].read_text()
    import re

    ips = {ipaddress.ip_address(m) for m in re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", text)}
    assert ips and all(any(ip in net for net in DOC_NETS) for ip in ips)


def test_ground_truth_round_trip(tmp_path):
    paths, gt = generate(tmp_path)
    loaded = GroundTruth.load(paths[2])
    assert loaded == gt
    assert {s.name for s in gt.scenarios} == {
        "ssh_brute_force_root",
        "ssh_password_spray",
        "webapp_admin_takeover",
        "off_hours_login",
        "low_and_slow_guessing",
    }


def test_baseline_has_no_attacks(tmp_path):
    _, gt = generate(tmp_path, attacks=False, quality_issues=False)
    assert gt.scenarios == [] and gt.injected_quality_issues == {}


def test_confusion_metrics():
    c = Confusion()
    for predicted, actual in [(1, 1), (1, 1), (1, 0), (0, 1), (0, 0)]:
        c.add(bool(predicted), bool(actual))
    assert (c.tp, c.fp, c.fn, c.tn) == (2, 1, 1, 1)
    assert c.precision == 2 / 3 and c.recall == 2 / 3
    assert Confusion().precision is None


def test_evaluate_without_anomalies(tmp_path):
    _, gt = generate(tmp_path)
    result = evaluate(gt, [], [], 60)
    assert all(r.ml_flagged is None for r in result.scenarios)
    assert result.windows == {}
    # no alerts at all: only the scenario that expects no rule is "ok"
    assert [r.scenario.name for r in result.scenarios if r.expected_ok] == ["low_and_slow_guessing"]
