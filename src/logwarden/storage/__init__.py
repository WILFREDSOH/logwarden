"""SQLite persistence for events, alerts, ingestion runs and ML anomaly scores.

* Every query is parameterised (no string formatting of user data into SQL).
* Events use their deterministic id as primary key, so re-ingesting a file is a no-op.
* Alerts are derived data: each detection run replaces them in one transaction.
* The dashboard opens the database read-only.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from logwarden.errors import StorageError
from logwarden.models import Alert, Event, EventType, ScoreItem, Severity

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events (
    event_id   TEXT PRIMARY KEY,
    ts         TEXT NOT NULL,          -- ISO 8601, UTC
    source     TEXT NOT NULL,
    event_type TEXT NOT NULL,
    username   TEXT,
    src_ip     TEXT,
    host       TEXT NOT NULL DEFAULT '',
    raw        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(src_ip);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id           TEXT PRIMARY KEY,
    rule_id            TEXT NOT NULL,
    severity           TEXT NOT NULL,
    score              INTEGER NOT NULL,
    first_seen         TEXT NOT NULL,
    last_seen          TEXT NOT NULL,
    username           TEXT,
    src_ip             TEXT,
    explanation_key    TEXT NOT NULL,
    explanation_params TEXT NOT NULL,  -- JSON
    score_breakdown    TEXT NOT NULL   -- JSON
);
CREATE TABLE IF NOT EXISTS alert_events (
    alert_id TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    event_id TEXT NOT NULL REFERENCES events(event_id),
    PRIMARY KEY (alert_id, event_id)
);
CREATE TABLE IF NOT EXISTS ingestion_runs (
    run_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    path        TEXT NOT NULL,
    fmt         TEXT NOT NULL,
    total_lines INTEGER NOT NULL,
    new_events  INTEGER NOT NULL,
    skipped     INTEGER NOT NULL,
    duplicates  INTEGER NOT NULL,
    malformed   INTEGER NOT NULL,
    malformed_detail TEXT NOT NULL     -- JSON {reason_key: count}
);
CREATE TABLE IF NOT EXISTS anomalies (
    src_ip       TEXT NOT NULL,
    window_start TEXT NOT NULL,
    score        REAL NOT NULL,        -- higher = more anomalous
    threshold    REAL NOT NULL,
    is_anomaly   INTEGER NOT NULL,
    features     TEXT NOT NULL,        -- JSON
    top_features TEXT NOT NULL,        -- JSON [[name, value, baseline_median], ...]
    PRIMARY KEY (src_ip, window_start)
);
"""


@dataclass(frozen=True)
class IngestionRun:
    started_at: str
    path: str
    fmt: str
    total_lines: int
    new_events: int
    skipped: int
    duplicates: int
    malformed: int
    malformed_detail: dict[str, int]


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat()


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _row_to_event(row: sqlite3.Row) -> Event:
    return Event(
        event_id=row["event_id"],
        timestamp=_dt(row["ts"]),
        source=row["source"],
        event_type=EventType(row["event_type"]),
        username=row["username"],
        src_ip=row["src_ip"],
        host=row["host"],
        raw=row["raw"],
    )


class Store:
    def __init__(self, path: str | Path, read_only: bool = False) -> None:
        self.path = Path(path)
        self.read_only = read_only
        try:
            if read_only:
                if not self.path.is_file():
                    raise StorageError("error.db_not_found", path=str(self.path))
                self.conn = sqlite3.connect(f"{self.path.resolve().as_uri()}?mode=ro", uri=True)
            else:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self.conn = sqlite3.connect(self.path)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA foreign_keys = ON")
            if not read_only:
                self.conn.executescript(_SCHEMA)
                self.conn.execute(
                    "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)",
                    (str(SCHEMA_VERSION),),
                )
                self.conn.commit()
            else:
                self.conn.execute("SELECT 1 FROM events LIMIT 1")
        except StorageError:
            raise
        except (sqlite3.Error, OSError) as exc:
            raise StorageError("error.db_open", path=str(self.path), detail=str(exc)) from exc

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        try:
            with self.conn:  # commits on success, rolls back on exception
                yield self.conn
        except sqlite3.Error as exc:
            raise StorageError("error.db_write", path=str(self.path), detail=str(exc)) from exc

    # ---- writes -------------------------------------------------------------
    def add_events(self, events: Iterable[Event]) -> int:
        """Insert events, ignoring ones already stored. Returns the number of new rows."""
        rows = [
            (
                e.event_id,
                _iso(e.timestamp),
                e.source,
                e.event_type.value,
                e.username,
                e.src_ip,
                e.host,
                e.raw,
            )
            for e in events
        ]
        with self._tx() as conn:
            before = conn.total_changes
            conn.executemany("INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?)", rows)
            return conn.total_changes - before

    def record_run(self, run: IngestionRun) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO ingestion_runs (started_at, path, fmt, total_lines, new_events, "
                "skipped, duplicates, malformed, malformed_detail) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    run.started_at,
                    run.path,
                    run.fmt,
                    run.total_lines,
                    run.new_events,
                    run.skipped,
                    run.duplicates,
                    run.malformed,
                    json.dumps(run.malformed_detail, sort_keys=True),
                ),
            )

    def replace_alerts(self, alerts: Iterable[Alert]) -> int:
        alerts = list(alerts)
        with self._tx() as conn:
            conn.execute("DELETE FROM alert_events")
            conn.execute("DELETE FROM alerts")
            conn.executemany(
                "INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        a.alert_id,
                        a.rule_id,
                        a.severity.value,
                        a.score,
                        _iso(a.first_seen),
                        _iso(a.last_seen),
                        a.username,
                        a.src_ip,
                        a.explanation_key,
                        json.dumps(a.explanation_params, sort_keys=True),
                        json.dumps([[i.label_key, i.points] for i in a.score_breakdown]),
                    )
                    for a in alerts
                ],
            )
            conn.executemany(
                "INSERT OR IGNORE INTO alert_events VALUES (?, ?)",
                [(a.alert_id, eid) for a in alerts for eid in a.event_ids],
            )
        return len(alerts)

    def replace_anomalies(self, rows: Iterable[dict[str, Any]]) -> int:
        rows = list(rows)
        with self._tx() as conn:
            conn.execute("DELETE FROM anomalies")
            conn.executemany(
                "INSERT INTO anomalies VALUES (?,?,?,?,?,?,?)",
                [
                    (
                        r["src_ip"],
                        r["window_start"],
                        r["score"],
                        r["threshold"],
                        int(r["is_anomaly"]),
                        json.dumps(r["features"], sort_keys=True),
                        json.dumps(r["top_features"]),
                    )
                    for r in rows
                ],
            )
        return len(rows)

    # ---- reads --------------------------------------------------------------
    def _query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        try:
            return self.conn.execute(sql, params).fetchall()
        except sqlite3.Error as exc:
            raise StorageError("error.db_read", path=str(self.path), detail=str(exc)) from exc

    def events(self) -> list[Event]:
        return [_row_to_event(r) for r in self._query("SELECT * FROM events ORDER BY ts, event_id")]

    def events_by_ids(self, event_ids: Iterable[str]) -> list[Event]:
        ids = list(event_ids)
        found: list[Event] = []
        for start in range(0, len(ids), 500):  # stay under SQLite's variable limit
            chunk = ids[start : start + 500]
            marks = ",".join("?" * len(chunk))
            sql = f"SELECT * FROM events WHERE event_id IN ({marks}) ORDER BY ts"  # noqa: S608 - only '?' placeholders
            found.extend(_row_to_event(r) for r in self._query(sql, tuple(chunk)))
        return sorted(found, key=lambda e: (e.timestamp, e.event_id))

    def alerts(self) -> list[Alert]:
        rows = self._query("SELECT * FROM alerts")
        links: dict[str, list[str]] = {}
        for link in self._query(
            "SELECT ae.alert_id, ae.event_id FROM alert_events ae "
            "JOIN events e USING (event_id) ORDER BY e.ts, e.event_id"
        ):
            links.setdefault(link["alert_id"], []).append(link["event_id"])
        from logwarden.detection import sort_alerts

        return sort_alerts(
            Alert(
                alert_id=r["alert_id"],
                rule_id=r["rule_id"],
                severity=Severity(r["severity"]),
                score=r["score"],
                first_seen=_dt(r["first_seen"]),
                last_seen=_dt(r["last_seen"]),
                username=r["username"],
                src_ip=r["src_ip"],
                event_ids=tuple(links.get(r["alert_id"], ())),
                explanation_key=r["explanation_key"],
                explanation_params=json.loads(r["explanation_params"]),
                score_breakdown=tuple(ScoreItem(k, p) for k, p in json.loads(r["score_breakdown"])),
            )
            for r in rows
        )

    def ingestion_runs(self) -> list[IngestionRun]:
        return [
            IngestionRun(
                started_at=r["started_at"],
                path=r["path"],
                fmt=r["fmt"],
                total_lines=r["total_lines"],
                new_events=r["new_events"],
                skipped=r["skipped"],
                duplicates=r["duplicates"],
                malformed=r["malformed"],
                malformed_detail=json.loads(r["malformed_detail"]),
            )
            for r in self._query("SELECT * FROM ingestion_runs ORDER BY run_id")
        ]

    def anomalies(self) -> list[dict[str, Any]]:
        return [
            {
                "src_ip": r["src_ip"],
                "window_start": r["window_start"],
                "score": r["score"],
                "threshold": r["threshold"],
                "is_anomaly": bool(r["is_anomaly"]),
                "features": json.loads(r["features"]),
                "top_features": json.loads(r["top_features"]),
            }
            for r in self._query("SELECT * FROM anomalies ORDER BY score DESC")
        ]

    def counts(self) -> dict[str, int]:
        row = self._query(
            "SELECT (SELECT COUNT(*) FROM events) AS events, "
            "(SELECT COUNT(*) FROM alerts) AS alerts"
        )[0]
        return {"events": row["events"], "alerts": row["alerts"]}
