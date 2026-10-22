"""Translation catalogue checks: a missing key or placeholder would leak raw text into the UI."""

import re
from pathlib import Path

import pytest

from logwarden.detection import RULE_IDS
from logwarden.errors import IngestionError
from logwarden.i18n import SUPPORTED_LANGS, _catalog, keys, resolve_lang, t
from logwarden.ml import FEATURES
from logwarden.models import EventType, Severity

SRC = Path(__file__).resolve().parents[2] / "src" / "logwarden"
PLACEHOLDER = re.compile(r"\{(\w+)\}")


def test_all_languages_have_the_same_keys():
    assert keys("en") == keys("fr")


@pytest.mark.parametrize("key", sorted(keys("en")))
def test_placeholders_match_between_languages(key):
    found = {lang: set(PLACEHOLDER.findall(_catalog(lang)[key])) for lang in SUPPORTED_LANGS}
    assert found["en"] == found["fr"], key


def test_every_literal_key_used_in_code_exists():
    pattern = re.compile(
        r"""(?:\bt|Error|Malformed|ScoreItem)\(\s*["']((?:error|cli|report|label|chart|ui|"""
        r"""malformed|score)\.[\w.-]+)["']"""
    )
    used = {m for path in SRC.rglob("*.py") for m in pattern.findall(path.read_text("utf-8"))}
    assert len(used) > 50  # sanity check that the scan works
    assert used - keys("en") == set()


def test_dynamic_keys_exist():
    needed = {f"severity.{s.value}" for s in Severity} | {
        f"event_type.{e.value}" for e in EventType
    }
    needed |= {f"feature.{f}" for f in FEATURES}
    needed |= {
        f"rule.{r}.{part}" for r in RULE_IDS for part in ("name", "short", "description", "action")
    }
    needed |= {f"explain.{r}" for r in RULE_IDS}
    assert needed - keys("en") == set()


def test_formatting_and_lists():
    assert t(
        "explain.LW-001",
        "en",
        count=5,
        ip="192.0.2.1",
        duration=1.0,
        threshold=5,
        window=5,
        users=["a", "b"],
    ).endswith("Targeted accounts: a, b.")
    assert t("severity.high", "fr") == "Élevée"


def test_fallbacks():
    assert t("no.such.key", "fr") == "no.such.key"
    assert (
        t("error.file_not_found", "fr") == _catalog("fr")["error.file_not_found"]
    )  # missing params
    assert resolve_lang("de") == "en"
    assert resolve_lang("FR") == "fr"


def test_language_from_environment(monkeypatch):
    monkeypatch.setenv("LOGWARDEN_LANG", "fr")
    assert resolve_lang(None) == "fr"


def test_errors_are_localised():
    err = IngestionError("error.file_not_found", path="x.log")
    assert err.localized("en") == "File not found: x.log"
    assert err.localized("fr") == "Fichier introuvable : x.log"
