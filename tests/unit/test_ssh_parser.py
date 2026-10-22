from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest

from logwarden.ingestion.common import Malformed, Skip
from logwarden.ingestion.ssh import SshParser
from logwarden.models import Event, EventType


@pytest.fixture
def parser() -> SshParser:
    return SshParser(year=2026, tz=ZoneInfo("UTC"))


def test_failed_password_existing_user(parser):
    ev = parser.parse_line(
        "Oct 14 10:02:13 web01 sshd[811]: Failed password for alice from 203.0.113.5 port 5022 ssh2"
    )
    assert isinstance(ev, Event)
    assert ev.event_type is EventType.AUTH_FAILURE
    assert (ev.username, ev.src_ip, ev.host, ev.source) == ("alice", "203.0.113.5", "web01", "ssh")
    assert ev.timestamp == datetime(2026, 10, 14, 10, 2, 13, tzinfo=UTC)


def test_failed_password_invalid_user(parser):
    ev = parser.parse_line(
        "Oct 14 10:02:13 web01 sshd[811]: Failed password for invalid user oracle "
        "from 198.51.100.9 port 40000 ssh2"
    )
    assert ev.event_type is EventType.INVALID_USER
    assert ev.username == "oracle"


@pytest.mark.parametrize("method", ["password", "publickey", "keyboard-interactive/pam"])
def test_accepted_methods(parser, method):
    ev = parser.parse_line(
        f"Oct  4 08:00:00 web01 sshd[1]: Accepted {method} for bob from 192.0.2.11 port 1 ssh2"
    )
    assert ev.event_type is EventType.AUTH_SUCCESS
    assert ev.timestamp.day == 4  # single-digit day padded with a space


def test_rfc3339_timestamp_converted_to_utc(parser):
    ev = parser.parse_line(
        "2026-10-14T12:02:13.123456+02:00 web01 sshd[811]: "
        "Accepted publickey for bob from 2001:db8::1 port 22 ssh2"
    )
    assert ev.timestamp == datetime(2026, 10, 14, 10, 2, 13, 123456, tzinfo=UTC)
    assert ev.src_ip == "2001:db8::1"


def test_traditional_timestamp_uses_given_timezone():
    parser = SshParser(year=2026, tz=ZoneInfo("Europe/Paris"))
    ev = parser.parse_line(
        "Oct 14 12:00:00 h sshd[1]: Failed password for a from 192.0.2.1 port 1 ssh2"
    )
    assert ev.timestamp == datetime(2026, 10, 14, 10, 0, tzinfo=UTC)  # CEST = UTC+2


@pytest.mark.parametrize(
    "line",
    [
        "Oct 14 10:00:00 h CRON[5]: pam_unix(cron:session): session opened for user root",
        "Oct 14 10:00:00 h sudo: alice : TTY=pts/0 ; COMMAND=/bin/ls",
        "Oct 14 10:00:00 h sshd[5]: Invalid user test from 198.51.100.1 port 22",
        "Oct 14 10:00:00 h sshd[5]: Received disconnect from 192.0.2.1 port 22:11: bye",
    ],
)
def test_non_authentication_lines_are_skipped(parser, line):
    assert isinstance(parser.parse_line(line), Skip)


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        ("complete garbage", "malformed.unrecognized_line"),
        ("", "malformed.unrecognized_line"),
        (
            "Feb 30 10:00:00 h sshd[1]: Failed password for a from 192.0.2.1 port 1 ssh2",
            "malformed.bad_timestamp",
        ),
        (
            "Oct 14 25:61:00 h sshd[1]: Failed password for a from 192.0.2.1 port 1 ssh2",
            "malformed.bad_timestamp",
        ),
        (
            "Oct 14 10:00:00 h sshd[1]: Failed password for a from 999.1.1.1 port 1 ssh2",
            "malformed.bad_ip",
        ),
        (
            "Oct 14 10:00:00 h sshd[1]: Failed password for a from not-an-ip port 1 ssh2",
            "malformed.bad_ip",
        ),
    ],
)
def test_malformed_lines(parser, line, reason):
    outcome = parser.parse_line(line)
    assert isinstance(outcome, Malformed)
    assert outcome.reason == reason


def test_year_rollover_december_to_january():
    parser = SshParser(year=2025, tz=ZoneInfo("UTC"))
    line = "{} h sshd[1]: Failed password for a from 192.0.2.1 port 1 ssh2"
    dec = parser.parse_line(line.format("Dec 31 23:59:59"))
    jan = parser.parse_line(line.format("Jan  1 00:00:01"))
    assert dec.timestamp.year == 2025
    assert jan.timestamp.year == 2026


def test_invalid_date_does_not_change_year_inference():
    parser = SshParser(year=2026, tz=ZoneInfo("UTC"))
    line = "{} h sshd[1]: Failed password for a from 192.0.2.1 port 1 ssh2"
    parser.parse_line(line.format("Oct 14 10:00:00"))
    assert isinstance(parser.parse_line(line.format("Feb 30 10:00:00")), Malformed)
    assert parser.parse_line(line.format("Oct 14 11:00:00")).timestamp.year == 2026


def test_control_characters_are_neutralised(parser):
    """A username containing an ANSI escape must not reach the terminal or the UI."""
    ev = parser.parse_line(
        "Oct 14 10:00:00 h sshd[1]: Failed password for invalid user \x1b[31mevil "
        "from 192.0.2.1 port 1 ssh2"
    )
    assert "\x1b" not in ev.username
    assert "\x1b" not in ev.raw


def test_raw_line_is_truncated():
    parser = SshParser(year=2026, tz=ZoneInfo("UTC"), raw_max_chars=40)
    ev = parser.parse_line(
        "Oct 14 10:00:00 h sshd[1]: Failed password for alice from 192.0.2.1 port 1 ssh2"
    )
    assert len(ev.raw) == 40


def test_same_line_gives_same_id(parser):
    line = "Oct 14 10:00:00 h sshd[1]: Failed password for a from 192.0.2.1 port 1 ssh2"
    assert parser.parse_line(line).event_id == parser.parse_line(line).event_id
