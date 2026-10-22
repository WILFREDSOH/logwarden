"""End-to-end: synthetic logs -> ingestion -> detection -> ML -> storage -> reports."""

from __future__ import annotations

import ipaddress
import json

import pytest

from logwarden.cli import main
from logwarden.config import load_config
from logwarden.evaluation import evaluate
from logwarden.models import Severity
from logwarden.storage import Store
from logwarden.synth import GroundTruth

pytest.importorskip("sklearn")
EMPLOYEE_NET = ipaddress.ip_network("192.0.2.0/24")


def run_demo(tmp_path, *extra):
    data, out = tmp_path / "data", tmp_path / "reports"
    code = main(["demo", "--data-dir", str(data), "--out", str(out), *extra])
    assert code == 0
    return data, out


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    data, out = run_demo(tmp_path_factory.mktemp("demo"))
    store = Store(data / "demo.db", read_only=True)
    gt = GroundTruth.load(data / "demo" / "ground_truth.json")
    yield store, gt, out
    store.close()


def test_every_scenario_triggers_its_expected_rules(demo):
    store, gt, _ = demo
    result = evaluate(gt, store.alerts(), store.anomalies(), load_config()["ml"]["window_minutes"])
    for r in result.scenarios:
        assert r.expected_ok, (r.scenario.name, r.rules_fired)
    assert result.alerts_outside_scenarios == 0


def test_normal_traffic_raises_no_high_or_critical_alert(demo):
    store, gt, _ = demo
    attack_ips = {s.src_ip for s in gt.scenarios}
    for alert in store.alerts():
        if alert.src_ip not in attack_ips:
            assert alert.severity.rank < Severity.HIGH.rank, alert


def test_expected_severities(demo):
    store, _, _ = demo
    top = {(a.rule_id, a.src_ip): a.severity for a in store.alerts()}
    assert top[("LW-003", "203.0.113.45")] is Severity.CRITICAL  # admin account takeover
    assert top[("LW-001", "203.0.113.10")] is Severity.HIGH  # brute force on root
    assert top[("LW-004", "192.0.2.13")] is Severity.LOW  # off-hours login


def test_ml_finds_the_attack_the_rules_miss(demo):
    """Documents current behaviour on the synthetic data (see docs/ml.md), not a general claim."""
    store, gt, _ = demo
    slow = next(s for s in gt.scenarios if s.name == "low_and_slow_guessing")
    assert not [a for a in store.alerts() if a.src_ip == slow.src_ip]
    assert any(r["is_anomaly"] for r in store.anomalies() if r["src_ip"] == slow.src_ip)


def test_data_quality_issues_are_counted_not_fatal(demo):
    store, _, _ = demo
    runs = {run.fmt: run for run in store.ingestion_runs()}
    assert runs["ssh"].malformed == 2 and runs["ssh"].duplicates == 1
    assert runs["webapp"].malformed == 2
    redacted = [e for e in store.events() if "[REDACTED]" in e.raw]
    assert len(redacted) == 1 and "not-a-real-password" not in redacted[0].raw


def test_reports_in_both_languages(demo):
    _, _, out = demo
    for lang in ("en", "fr"):
        text = (out / f"report.{lang}.md").read_text("utf-8")
        assert "LW-003" in text and "low_and_slow_guessing" in text
        for chart in ("alerts_by_severity", "alerts_by_rule", "timeline", "top_failure_ips"):
            assert (out / "charts" / lang / f"{chart}.png").stat().st_size > 1000
        assert json.loads((out / f"alerts.{lang}.json").read_text("utf-8"))
    assert "Rapport d'analyse" in (out / "report.fr.md").read_text("utf-8")


def test_demo_is_reproducible(tmp_path, demo):
    store, _, _ = demo
    data, _ = run_demo(tmp_path)
    with Store(data / "demo.db", read_only=True) as again:
        assert [a.alert_id for a in again.alerts()] == [a.alert_id for a in store.alerts()]
        assert again.anomalies() == store.anomalies()


def test_reingesting_the_same_files_is_idempotent(tmp_path):
    data, _ = run_demo(tmp_path, "--no-ml")
    db = data / "demo.db"
    logs = [str(data / "demo" / "auth.log"), str(data / "demo" / "app_auth.jsonl")]
    with Store(db, read_only=True) as s:
        before = s.counts()["events"]
    assert main(["ingest", *logs, "--db", str(db), "--year", "2026"]) == 0
    with Store(db, read_only=True) as s:
        assert s.counts()["events"] == before
        assert s.ingestion_runs()[-1].new_events == 0
