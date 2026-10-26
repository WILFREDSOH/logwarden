"""Headless dashboard tests with Streamlit's AppTest (no browser needed)."""

from pathlib import Path

import pytest

from logwarden.cli import main

pytest.importorskip("streamlit")
pytest.importorskip("sklearn")
from streamlit.testing.v1 import AppTest  # noqa: E402

APP = str(Path(__file__).resolve().parents[2] / "src" / "logwarden" / "dashboard" / "app.py")


@pytest.fixture(scope="module")
def demo_db(tmp_path_factory):
    base = tmp_path_factory.mktemp("dash")
    assert main(["demo", "--data-dir", str(base / "data"), "--out", str(base / "r")]) == 0
    return base / "data" / "demo.db"


def run_app(monkeypatch, db, lang="en"):
    monkeypatch.setenv("LOGWARDEN_DB", str(db))
    monkeypatch.setenv("LOGWARDEN_LANG", lang)
    return AppTest.from_file(APP, default_timeout=60).run()


def test_dashboard_renders_in_english(monkeypatch, demo_db):
    at = run_app(monkeypatch, demo_db)
    assert not at.exception
    assert at.title[0].value == "LogWarden"
    assert [tab.label for tab in at.tabs] == [
        "Overview",
        "Alerts",
        "Events",
        "Anomalies (ML)",
        "Data quality",
        "Analyze a file",
    ]
    assert at.metric[0].value == "334" and at.metric[1].value == "9"
    assert at.error  # critical alert details are shown in an error box


def test_language_switch(monkeypatch, demo_db):
    at = run_app(monkeypatch, demo_db)
    at.sidebar.radio[0].set_value("fr").run()
    assert not at.exception
    assert at.tabs[0].label == "Vue d'ensemble"
    assert "s'est connecté avec succès" in at.error[0].value


def test_alert_filters(monkeypatch, demo_db):
    at = run_app(monkeypatch, demo_db)
    at.multiselect[0].set_value(["low"]).run()
    assert not at.exception
    assert "1 shown out of 9" in [c.value for c in at.caption]


def test_missing_database_shows_an_error(monkeypatch, tmp_path):
    at = run_app(monkeypatch, tmp_path / "missing.db", lang="fr")
    assert not at.exception
    assert "Base de données introuvable" in at.error[0].value


def test_sandbox_tab_without_upload(monkeypatch, demo_db):
    at = run_app(monkeypatch, demo_db, lang="fr")
    assert not at.exception
    assert at.tabs[5].label == "Analyser un fichier"
    assert any("Aucun fichier" in i.value for i in at.info)
    assert any("N'envoyez pas" in w.value for w in at.warning)
