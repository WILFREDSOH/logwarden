"""Configuration loading and validation.

Defaults ship inside the package (`default_config.toml`); a user file only needs
to contain the keys it overrides. Unknown keys and wrong types are rejected so
that a typo never silently disables a rule.
"""

from __future__ import annotations

import tomllib
from importlib import resources
from pathlib import Path
from typing import Any

from logwarden.errors import ConfigError


def _defaults() -> dict[str, Any]:
    text = resources.files("logwarden").joinpath("default_config.toml").read_text("utf-8")
    return tomllib.loads(text)


def _merge(base: dict[str, Any], override: dict[str, Any], path: str = "") -> None:
    for key, value in override.items():
        where = f"{path}.{key}" if path else key
        if key not in base:
            raise ConfigError("error.config_unknown_key", key=where)
        current = base[key]
        if isinstance(current, dict):
            if not isinstance(value, dict):
                raise ConfigError("error.config_type", key=where, expected="table")
            _merge(current, value, where)
            continue
        if not _same_type(current, value):
            raise ConfigError("error.config_type", key=where, expected=type(current).__name__)
        base[key] = value


def _same_type(default: Any, value: Any) -> bool:
    # bool is a subclass of int: handle it first so `threshold = true` is refused.
    if isinstance(default, bool) or isinstance(value, bool):
        return isinstance(default, bool) and isinstance(value, bool)
    if isinstance(default, float):
        return isinstance(value, (int, float))
    if isinstance(default, list):
        if not isinstance(value, list):
            return False
        return not default or all(_same_type(default[0], item) for item in value)
    return isinstance(value, type(default))


def _validate(cfg: dict[str, Any]) -> None:
    def positive(section: dict[str, Any], key: str, where: str) -> None:
        if section[key] <= 0:
            raise ConfigError("error.config_value", key=f"{where}.{key}")

    for key in ("max_file_size_mb", "max_line_length", "raw_max_chars"):
        positive(cfg["ingestion"], key, "ingestion")
    for rule_id, rule in cfg["rules"].items():
        for key, value in rule.items():
            if (
                isinstance(value, int)
                and not isinstance(value, bool)
                and key != "business_start_hour"
            ):
                positive(rule, key, f"rules.{rule_id}")
    office = cfg["rules"]["LW-004"]
    if not 0 <= office["business_start_hour"] < office["business_end_hour"] <= 24:
        raise ConfigError("error.config_value", key="rules.LW-004.business_*_hour")
    if not 0 < cfg["ml"]["contamination_quantile"] < 0.5:
        raise ConfigError("error.config_value", key="ml.contamination_quantile")


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    cfg = _defaults()
    if path is not None:
        path = Path(path)
        try:
            override = tomllib.loads(path.read_text("utf-8"))
        except FileNotFoundError as exc:
            raise ConfigError("error.config_not_found", path=str(path)) from exc
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            raise ConfigError("error.config_invalid", path=str(path), detail=str(exc)) from exc
        _merge(cfg, override)
    _validate(cfg)
    return cfg
