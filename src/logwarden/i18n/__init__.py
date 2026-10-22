"""Minimal translation layer (no external dependency).

Every user-visible string lives in `locales/<lang>.json` and is looked up by key.
Alerts store a key + parameters instead of a rendered sentence, so the same
database can be displayed in any supported language.
"""

from __future__ import annotations

import json
import os
from functools import cache
from importlib import resources

SUPPORTED_LANGS = ("en", "fr")
DEFAULT_LANG = "en"


@cache
def _catalog(lang: str) -> dict[str, str]:
    text = resources.files("logwarden.i18n").joinpath(f"locales/{lang}.json").read_text("utf-8")
    return json.loads(text)


def resolve_lang(lang: str | None = None) -> str:
    """Pick the language: explicit value, then $LOGWARDEN_LANG, then English."""
    candidate = (lang or os.environ.get("LOGWARDEN_LANG") or DEFAULT_LANG).lower()[:2]
    return candidate if candidate in SUPPORTED_LANGS else DEFAULT_LANG


def _fmt(value: object) -> object:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return value


def t(key: str, lang: str | None = None, **params: object) -> str:
    """Translate `key`, falling back to English, then to the key itself."""
    lang = resolve_lang(lang)
    template = _catalog(lang).get(key) or _catalog(DEFAULT_LANG).get(key) or key
    if not params:
        return template
    try:
        return template.format(**{k: _fmt(v) for k, v in params.items()})
    except (KeyError, IndexError, ValueError):
        # A malformed template must never crash the UI; show it unformatted.
        return template


def keys(lang: str) -> set[str]:
    return set(_catalog(lang))
