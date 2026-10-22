"""Parser for the JSON Lines authentication log of the demo web application.

Expected record (one JSON object per line):
    {"ts": "2026-10-12T09:14:03Z", "app": "intranet", "event": "login_failed",
     "user": "alice", "ip": "192.0.2.10", "reason": "bad_password"}

`event` is "login_success" or "login_failed"; `reason: "unknown_user"` marks an
attempt against a non-existent account. Other event types (logout, page_view)
are skipped. Sensitive keys (password, token...) are removed before storage.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime

from logwarden.ingestion.common import (
    SKIP,
    Malformed,
    ParseOutcome,
    clean_username,
    sanitize,
    valid_ip,
)
from logwarden.models import Event, EventType, utc

_EVENT_TYPES = {"login_success": EventType.AUTH_SUCCESS, "login_failed": EventType.AUTH_FAILURE}


class WebAppParser:
    source = "webapp"

    def __init__(self, redacted_fields: Iterable[str] = (), raw_max_chars: int = 500) -> None:
        self.redacted = {f.lower() for f in redacted_fields}
        self.raw_max_chars = raw_max_chars

    def _redact(self, record: dict) -> dict:
        return {k: ("[REDACTED]" if k.lower() in self.redacted else v) for k, v in record.items()}

    def parse_line(self, line: str) -> ParseOutcome:
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, RecursionError):
            return Malformed("malformed.bad_json")
        if not isinstance(record, dict):
            return Malformed("malformed.bad_json")

        event = record.get("event")
        if not isinstance(event, str):
            return Malformed("malformed.missing_field")
        kind = _EVENT_TYPES.get(event)
        if kind is None:
            return SKIP

        ts_value = record.get("ts")
        if not isinstance(ts_value, str):
            return Malformed("malformed.missing_field")
        try:
            ts = utc(datetime.fromisoformat(ts_value))  # naive timestamps are read as UTC
        except ValueError:
            return Malformed("malformed.bad_timestamp")

        ip = valid_ip(record.get("ip"))
        if ip is None:
            return Malformed("malformed.bad_ip")
        if kind is EventType.AUTH_FAILURE and record.get("reason") == "unknown_user":
            kind = EventType.INVALID_USER

        raw = sanitize(json.dumps(self._redact(record), sort_keys=True), self.raw_max_chars)
        app = record.get("app")
        return Event(
            event_id=Event.make_id(self.source, ts, raw),
            timestamp=ts,
            source=self.source,
            event_type=kind,
            username=clean_username(record.get("user")),
            src_ip=ip,
            host=sanitize(app, 64) if isinstance(app, str) else "webapp",
            raw=raw,
        )
