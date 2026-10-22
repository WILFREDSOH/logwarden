"""Helpers shared by the parsers."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from logwarden.models import Event

# C0/C1 control characters (incl. ESC): stripped so that a crafted log line cannot
# inject ANSI escape sequences into an analyst's terminal or break the UI.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
MAX_USERNAME = 64


def sanitize(text: str, max_chars: int) -> str:
    cleaned = _CONTROL.sub("?", text)
    return cleaned if len(cleaned) <= max_chars else cleaned[: max_chars - 1] + "…"


def clean_username(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = sanitize(value.strip(), MAX_USERNAME)
    return value or None


def valid_ip(value: object) -> str | None:
    """Return the canonical form of an IPv4/IPv6 address, or None if invalid."""
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class Skip:
    """A well-formed line that carries no authentication event (cron, logout...)."""


@dataclass(frozen=True, slots=True)
class Malformed:
    reason: str  # i18n key, e.g. "malformed.bad_timestamp"


ParseOutcome = Event | Skip | Malformed
SKIP = Skip()
