"""CLI behaviour: commands, exit codes and localised error messages."""

import pytest

from logwarden import __version__
from logwarden.cli import main
from logwarden.synth import generate


@pytest.fixture
def logs(tmp_path):
    paths, _ = generate(tmp_path / "logs")
    return [str(p) for p in paths[:2]]


def test_step_by_step_workflow(tmp_path, logs, capsys):
    db = str(tmp_path / "lw.db")
    assert main(["ingest", *logs, "--db", db, "--year", "2026"]) == 0
    assert main(["detect", "--db", db]) == 0
    assert main(["report", "--db", db, "--out", str(tmp_path / "r"), "--lang", "fr"]) == 0
    assert main(["alerts", "--db", db, "--min-severity", "critical"]) == 0
    out = capsys.readouterr().out
    assert "9 alerts from 334 events" in out
    assert "Rapport écrit" in out
    assert out.count("[CRITICAL") == 2
    assert (tmp_path / "r" / "report.fr.md").exists()


def test_generate_command(tmp_path, capsys):
    assert main(["generate", "--out", str(tmp_path / "g"), "--baseline"]) == 0
    assert (tmp_path / "g" / "auth.log").exists()


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_unknown_command_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["explode"])
    assert exc.value.code == 2


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["ingest", "nope.log", "--lang", "fr"], "Fichier introuvable : nope.log"),
        (["ingest", "nope.log", "--lang", "en"], "File not found: nope.log"),
        (["report", "--db", "missing.db"], "Database not found"),
        (["alerts", "--db", "missing.db", "--lang", "fr"], "Base de données introuvable"),
        (["detect", "--config", "missing.toml"], "Configuration file not found"),
    ],
)
def test_errors_are_reported_in_the_chosen_language(tmp_path, monkeypatch, capsys, argv, expected):
    monkeypatch.chdir(tmp_path)
    assert main(argv) == 1
    assert expected in capsys.readouterr().err


def test_detect_on_empty_database(tmp_path, capsys):
    assert main(["detect", "--db", str(tmp_path / "empty.db")]) == 1
    assert "no events" in capsys.readouterr().err


def test_language_from_environment(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("LOGWARDEN_LANG", "fr")
    monkeypatch.chdir(tmp_path)
    assert main(["ingest", "nope.log"]) == 1
    assert "Erreur" in capsys.readouterr().err


def test_custom_config_changes_detection(tmp_path, logs, capsys):
    cfg = tmp_path / "strict.toml"
    cfg.write_text("[rules.LW-004]\nenabled = false\n", encoding="utf-8")
    db = str(tmp_path / "lw.db")
    main(["ingest", *logs, "--db", db, "--year", "2026"])
    assert main(["detect", "--db", db, "--config", str(cfg)]) == 0
    assert "7 alerts" in capsys.readouterr().out  # the two LW-004 alerts are gone
