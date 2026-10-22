"""User-facing errors carry an i18n key so they can be shown in French or English."""

from __future__ import annotations


class LogWardenError(Exception):
    def __init__(self, key: str, **params: object) -> None:
        self.key = key
        self.params = params
        super().__init__(f"{key} {params}" if params else key)

    def localized(self, lang: str) -> str:
        from logwarden.i18n import t

        return t(self.key, lang, **self.params)


class IngestionError(LogWardenError):
    """The input file cannot be read at all (missing, too large, wrong type...)."""


class ConfigError(LogWardenError):
    """The configuration file is invalid."""


class StorageError(LogWardenError):
    """The SQLite database cannot be opened, read or written."""
