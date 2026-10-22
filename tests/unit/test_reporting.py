import csv
import json

from logwarden.dashboard import md_escape
from logwarden.detection import run_detection
from logwarden.models import EventType
from logwarden.reporting import _csv_safe, explain, export_alerts, score_text
from logwarden.reporting.charts import render_all
from logwarden.reporting.markdown import _cell, build_report
from logwarden.reporting.stats import summarize


def scenario(cfg, failures, make_event):
    events = [
        *failures(6, gap=10, user="root"),
        make_event(70, EventType.AUTH_SUCCESS, user="root"),
    ]
    return events, run_detection(events, cfg)


def test_explanations_in_both_languages(cfg, failures, make_event):
    _, alerts = scenario(cfg, failures, make_event)
    lw003 = next(a for a in alerts if a.rule_id == "LW-003")
    assert "logged in successfully" in explain(lw003, "en")
    assert "s'est connecté avec succès" in explain(lw003, "fr")
    assert score_text(lw003, "en").endswith(f"= {lw003.score}")


def test_csv_injection_is_neutralised():
    assert _csv_safe('=HYPERLINK("http://x")') == '\'=HYPERLINK("http://x")'
    assert _csv_safe("@SUM(A1)") == "'@SUM(A1)"
    assert _csv_safe("alice") == "alice" and _csv_safe(5) == 5


def test_export_files(tmp_path, cfg, failures, make_event):
    _, alerts = scenario(cfg, failures, make_event)
    json_path, csv_path = export_alerts(alerts, "fr", tmp_path)
    records = json.loads(json_path.read_text("utf-8"))
    assert len(records) == len(alerts) and records[0]["severity_label"] in {"Critique", "Élevée"}
    with csv_path.open(encoding="utf-8") as fh:
        assert len(list(csv.DictReader(fh))) == len(alerts)


def test_export_without_alerts(tmp_path):
    _, csv_path = export_alerts([], "en", tmp_path)
    assert csv_path.read_text("utf-8").startswith("alert_id,rule_id")


def test_markdown_cells_are_escaped():
    assert _cell("a|b\nc") == "a\\|b c"


def test_dashboard_markdown_escape():
    assert md_escape("![x](http://evil/p.png)") == "\\!\\[x\\]\\(http://evil/p\\.png\\)"


def test_report_and_charts(tmp_path, cfg, failures, make_event):
    events, alerts = scenario(cfg, failures, make_event)
    summary = summarize(events, alerts, [])
    assert summary.events_total == 7 and summary.by_severity["critical"] >= 1
    charts = render_all(summary, "en", tmp_path)
    assert {p.name for p in charts} >= {"alerts_by_severity.png", "timeline.png"}
    assert all(p.stat().st_size > 1000 for p in charts)
    text = build_report(summary, alerts, {}, "fr", {"severity": "charts/x.png"})
    assert text.startswith("# LogWarden - Rapport")
    assert "LW-003" in text and "![Alertes par sévérité](charts/x.png)" in text


def test_report_with_no_data(tmp_path):
    summary = summarize([], [], [])
    assert render_all(summary, "en", tmp_path)  # severity chart is always produced
    assert "No alerts." in build_report(summary, [], {}, "en", {})
