import pytest

from logwarden.config import load_config
from logwarden.errors import ConfigError


def write(tmp_path, text):
    path = tmp_path / "c.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_defaults_are_valid():
    cfg = load_config()
    assert cfg["rules"]["LW-001"]["threshold"] == 5
    assert set(cfg["rules"]) == {"LW-001", "LW-002", "LW-003", "LW-004", "LW-005"}


def test_partial_override_keeps_other_defaults(tmp_path):
    cfg = load_config(
        write(tmp_path, "[rules.LW-001]\nthreshold = 10\n[ml]\ncontamination_quantile = 0.05")
    )
    assert cfg["rules"]["LW-001"]["threshold"] == 10
    assert cfg["rules"]["LW-001"]["window_minutes"] == 5
    assert cfg["ml"]["contamination_quantile"] == 0.05


@pytest.mark.parametrize(
    ("text", "key"),
    [
        ("[rules.LW-001]\nthreshhold = 3", "error.config_unknown_key"),  # typo must not be ignored
        ("[rules.LW-001]\nthreshold = true", "error.config_type"),
        ("[rules.LW-001]\nthreshold = '5'", "error.config_type"),
        ("[scoring]\nprivileged_accounts = [1, 2]", "error.config_type"),
        ("rules = 3", "error.config_type"),
        ("[rules.LW-001]\nthreshold = 0", "error.config_value"),
        ("[rules.LW-004]\nbusiness_start_hour = 20\nbusiness_end_hour = 8", "error.config_value"),
        ("[ml]\ncontamination_quantile = 0.9", "error.config_value"),
        ("this is = = not toml", "error.config_invalid"),
    ],
)
def test_invalid_configurations(tmp_path, text, key):
    with pytest.raises(ConfigError) as err:
        load_config(write(tmp_path, text))
    assert err.value.key == key


def test_missing_file(tmp_path):
    with pytest.raises(ConfigError) as err:
        load_config(tmp_path / "nope.toml")
    assert err.value.key == "error.config_not_found"
