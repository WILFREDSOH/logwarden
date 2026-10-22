"""Parser for OpenSSH authentication messages in syslog files (/var/log/auth.log).

Two timestamp styles are supported:
  * traditional syslog:  ``Oct 22 10:02:13 web01 sshd[1234]: ...``  (no year, local time)
  * RFC 3339 (rsyslog default on recent Ubuntu):
    ``2026-10-22T10:02:13.123+02:00 web01 sshd[1234]: ...``

Only sshd authentication outcomes become events; other well-formed lines
(cron, sudo, sshd disconnects...) are skipped, not treated as errors.
"""

from __future__ import annotations

import re
from datetime import datetime, tzinfo

from logwarden.ingestion.common import (
    SKIP,
    Malformed,
    ParseOutcome,
    clean_username,
    sanitize,
    valid_ip,
)
from logwarden.models import Event, EventType, utc

_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1
    )
}

_TRADITIONAL = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<prog>[^\s\[:]+)(?:\[\d+\])?: (?P<msg>.*)$"
)
_RFC3339 = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})) "
    r"(?P<host>\S+) (?P<prog>[^\s\[:]+)(?:\[\d+\])?: (?P<msg>.*)$"
)
_METHODS = r"(?:password|publickey|keyboard-interactive/pam|hostbased)"
_FAILED = re.compile(
    rf"^Failed {_METHODS} for (?P<invalid>invalid user )?(?P<user>.*?) "
    r"from (?P<ip>\S+) port \d+"
)
_ACCEPTED = re.compile(rf"^Accepted {_METHODS} for (?P<user>.*?) from (?P<ip>\S+) port \d+")


class SshParser:
    """Stateful parser: it tracks the month to infer the year across New Year."""

    source = "ssh"

    def __init__(self, year: int, tz: tzinfo, raw_max_chars: int = 500) -> None:
        self.year = year
        self.tz = tz
        self.raw_max_chars = raw_max_chars
        self._last_month: int | None = None

    def _traditional_ts(self, mon: str, day: str, clock: str) -> datetime | None:
        month = _MONTHS.get(mon)
        if month is None:
            return None
        # Syslog has no year: a jump from December back to January means a new year.
        year = self.year
        if self._last_month is not None and self._last_month - month > 6:
            year += 1
        try:
            hour, minute, second = (int(x) for x in clock.split(":"))
            local = datetime(year, month, int(day), hour, minute, second, tzinfo=self.tz)
        except ValueError:  # e.g. Feb 30 or 25:00:00 - must not change the parser state
            return None
        self.year, self._last_month = year, month
        return utc(local)

    def parse_line(self, line: str) -> ParseOutcome:
        match = _TRADITIONAL.match(line)
        if match:
            ts = self._traditional_ts(match["mon"], match["day"], match["time"])
        else:
            match = _RFC3339.match(line)
            if not match:
                return Malformed("malformed.unrecognized_line")
            try:
                ts = utc(datetime.fromisoformat(match["ts"]))
            except ValueError:
                ts = None
        if ts is None:
            return Malformed("malformed.bad_timestamp")

        if not match["prog"].startswith("sshd"):
            return SKIP
        msg = match["msg"]
        if found := _FAILED.match(msg):
            kind = EventType.INVALID_USER if found["invalid"] else EventType.AUTH_FAILURE
        elif found := _ACCEPTED.match(msg):
            kind = EventType.AUTH_SUCCESS
        else:
            # e.g. "Invalid user x from ..." (always followed by a "Failed ... invalid user"
            # line we already count), "Disconnected from", "Received disconnect"...
            return SKIP

        ip = valid_ip(found["ip"])
        if ip is None:
            return Malformed("malformed.bad_ip")
        raw = sanitize(line, self.raw_max_chars)
        return Event(
            event_id=Event.make_id(self.source, ts, raw),
            timestamp=ts,
            source=self.source,
            event_type=kind,
            username=clean_username(found["user"]),
            src_ip=ip,
            host=sanitize(match["host"], 64),
            raw=raw,
        )
