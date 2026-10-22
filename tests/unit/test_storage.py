import sqlite3

import pytest

from logwarden.detection import run_detection
from logwarden.errors import StorageError
from logwarden.models import EventType
from logwarden.storage import IngestionRun, Store


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "db" / "lw.db") as s:  # parent directory is created
        yield s


def test_events_round_trip_and_idempotent_insert(store, failures):
    events = failures(3, gap=10)
    assert store.add_events(events) == 3
    assert store.add_events(events) == 0  # same ids: ignored
    assert store.events() == events


def test_alerts_round_trip_and_replace(store, cfg, failures, make_event):
    events = [
        *failures(6, gap=10, user="root"),
        make_event(70, EventType.AUTH_SUCCESS, user="root"),
    ]
    store.add_events(events)
    alerts = run_detection(events, cfg)
    store.replace_alerts(alerts)
    assert store.alerts() == alerts  # including event ids, params and score breakdown
    store.replace_alerts(alerts[:1])
    assert store.counts() == {"events": 7, "alerts": 1}


def test_events_by_ids_handles_many_ids(store, failures):
    events = failures(1200, gap=1)
    store.add_events(events)
    found = store.events_by_ids([e.event_id for e in events])
    assert len(found) == 1200


def test_ingestion_runs_and_anomalies(store):
    run = IngestionRun(
        "2026-10-22T10:00:00", "a.log", "ssh", 10, 5, 3, 1, 1, {"malformed.bad_ip": 1}
    )
    store.record_run(run)
    assert store.ingestion_runs() == [run]
    row = {
        "src_ip": "192.0.2.1",
        "window_start": "2026-10-14T10:00:00+00:00",
        "score": 0.7,
        "threshold": 0.6,
        "is_anomaly": True,
        "features": {"n_events": 3},
        "top_features": [["n_events", 3, 1]],
    }
    store.replace_anomalies([row])
    assert store.anomalies() == [row]


def test_sql_injection_payload_is_stored_as_data(store, make_event):
    event = make_event(user="x'); DROP TABLE events; --")
    store.add_events([event])
    assert store.events()[0].username == "x'); DROP TABLE events; --"


def test_read_only_store_refuses_writes(tmp_path, failures):
    path = tmp_path / "lw.db"
    Store(path).close()
    with Store(path, read_only=True) as ro:
        with pytest.raises(StorageError) as err:
            ro.add_events(failures(1, gap=1))
    assert err.value.key == "error.db_write"


def test_read_only_missing_database(tmp_path):
    with pytest.raises(StorageError) as err:
        Store(tmp_path / "missing.db", read_only=True)
    assert err.value.key == "error.db_not_found"


@pytest.mark.parametrize("read_only", [False, True])
def test_corrupted_database_file(tmp_path, read_only):
    path = tmp_path / "corrupt.db"
    path.write_bytes(b"this is not a sqlite database" * 100)
    with pytest.raises(StorageError) as err:
        Store(path, read_only=read_only)
    assert err.value.key == "error.db_open"


def test_database_in_unwritable_location(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    with pytest.raises(StorageError):
        Store(blocker / "sub" / "lw.db")  # parent "directory" is a file


def test_failed_transaction_is_rolled_back(store, cfg, failures):
    events = failures(5, gap=10)
    store.add_events(events)
    alerts = run_detection(events, cfg)
    store.replace_alerts(alerts)
    duplicate = alerts + alerts  # violates the alerts primary key
    with pytest.raises(StorageError):
        store.replace_alerts(duplicate)
    assert store.alerts() == alerts  # previous alerts still there


def test_foreign_keys_enforced(store):
    with pytest.raises(sqlite3.IntegrityError):
        store.conn.execute("INSERT INTO alert_events VALUES ('nope', 'nope')")
