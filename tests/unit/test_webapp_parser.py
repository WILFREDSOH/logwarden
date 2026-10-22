import json
from datetime import UTC, datetime

import pytest

from logwarden.ingestion.common import Malformed, Skip
from logwarden.ingestion.webapp import WebAppParser
from logwarden.models import Event, EventType

BASE = {"ts": "2026-10-14T10:00:00Z", "app": "intranet", "user": "alice", "ip": "192.0.2.10"}


@pytest.fixture
def parser() -> WebAppParser:
    return WebAppParser(redacted_fields=["password", "token"])


def line(**fields) -> str:
    return json.dumps({**BASE, **fields})


def test_success(parser):
    ev = parser.parse_line(line(event="login_success"))
    assert isinstance(ev, Event)
    assert ev.event_type is EventType.AUTH_SUCCESS
    assert ev.timestamp == datetime(2026, 10, 14, 10, 0, tzinfo=UTC)
    assert (ev.username, ev.src_ip, ev.host, ev.source) == (
        "alice",
        "192.0.2.10",
        "intranet",
        "webapp",
    )


def test_failure_and_unknown_user(parser):
    assert parser.parse_line(line(event="login_failed", reason="bad_password")).event_type is (
        EventType.AUTH_FAILURE
    )
    assert parser.parse_line(line(event="login_failed", reason="unknown_user")).event_type is (
        EventType.INVALID_USER
    )


def test_timezone_offset_and_naive_timestamps(parser):
    ev = parser.parse_line(line(event="login_success", ts="2026-10-14T12:00:00+02:00"))
    assert ev.timestamp == datetime(2026, 10, 14, 10, 0, tzinfo=UTC)
    naive = parser.parse_line(line(event="login_success", ts="2026-10-14T10:00:00"))
    assert naive.timestamp == datetime(2026, 10, 14, 10, 0, tzinfo=UTC)  # documented: read as UTC


@pytest.mark.parametrize("event", ["logout", "page_view", "password_reset"])
def test_other_events_are_skipped(parser, event):
    assert isinstance(parser.parse_line(line(event=event)), Skip)


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ('{"ts": "2026-10-14T10:00:00Z", "event": "login_fa', "malformed.bad_json"),
        ("[1, 2, 3]", "malformed.bad_json"),
        ('"just a string"', "malformed.bad_json"),
        (line(event=["login_success"]), "malformed.missing_field"),
        (json.dumps({"ts": "2026-10-14T10:00:00Z", "ip": "192.0.2.1"}), "malformed.missing_field"),
        (line(event="login_success", ts=None), "malformed.missing_field"),
        (line(event="login_success", ts="14/10/2026 10:00"), "malformed.bad_timestamp"),
        (line(event="login_success", ip="300.1.1.1"), "malformed.bad_ip"),
        (line(event="login_success", ip=None), "malformed.bad_ip"),
    ],
)
def test_malformed_records(parser, text, reason):
    outcome = parser.parse_line(text)
    assert isinstance(outcome, Malformed)
    assert outcome.reason == reason


def test_deeply_nested_json_does_not_crash(parser):
    assert isinstance(parser.parse_line("[" * 100_000 + "]" * 100_000), Malformed)


def test_sensitive_fields_are_redacted(parser):
    ev = parser.parse_line(line(event="login_failed", Password="hunter2", token="abc"))
    assert "hunter2" not in ev.raw and "abc" not in ev.raw
    assert ev.raw.count("[REDACTED]") == 2


def test_non_string_user_becomes_none(parser):
    assert parser.parse_line(line(event="login_success", user=42)).username is None
