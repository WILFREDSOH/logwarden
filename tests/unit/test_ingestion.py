import json

import pytest

from logwarden.errors import IngestionError
from logwarden.ingestion import ingest_file

SSH = "Oct 14 10:00:0{i} h sshd[1]: Failed password for alice from 192.0.2.1 port 1 ssh2"


def write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_empty_file(tmp_path, cfg):
    result = ingest_file(write(tmp_path, "auth.log", ""), cfg, year=2026)
    assert result.events == [] and result.total_lines == 0 and result.malformed_total == 0


def test_blank_lines_only(tmp_path, cfg):
    result = ingest_file(write(tmp_path, "auth.log", "\n  \n\n"), cfg, year=2026)
    assert result.events == [] and result.blank_lines == 3


def test_counts_and_duplicates(tmp_path, cfg):
    lines = [SSH.format(i=1), SSH.format(i=2), SSH.format(i=1), "garbage", ""]
    result = ingest_file(write(tmp_path, "auth.log", "\n".join(lines)), cfg, year=2026)
    assert len(result.events) == 2
    assert result.duplicates == 1
    assert result.malformed_total == 1
    assert result.errors == [(4, "malformed.unrecognized_line")]


def test_dedup_across_files_with_shared_seen_set(tmp_path, cfg):
    a = write(tmp_path, "a.log", SSH.format(i=1))
    b = write(tmp_path, "b.log", SSH.format(i=1))
    seen: set[str] = set()
    assert len(ingest_file(a, cfg, year=2026, seen_ids=seen).events) == 1
    assert ingest_file(b, cfg, year=2026, seen_ids=seen).duplicates == 1


def test_format_auto_detection(tmp_path, cfg):
    record = json.dumps(
        {"ts": "2026-10-14T10:00:00Z", "event": "login_success", "user": "a", "ip": "192.0.2.1"}
    )
    assert ingest_file(write(tmp_path, "x.jsonl", record), cfg).fmt == "webapp"
    assert ingest_file(write(tmp_path, "x.txt", record), cfg).fmt == "webapp"  # content sniffing
    assert ingest_file(write(tmp_path, "auth.log", SSH.format(i=1)), cfg, year=2026).fmt == "ssh"


def test_forced_wrong_format_marks_lines_malformed(tmp_path, cfg):
    result = ingest_file(write(tmp_path, "auth.log", SSH.format(i=1)), cfg, fmt="webapp")
    assert result.events == [] and result.malformed == {"malformed.bad_json": 1}


def test_too_long_line(tmp_path, cfg):
    cfg["ingestion"]["max_line_length"] = 50
    result = ingest_file(write(tmp_path, "auth.log", SSH.format(i=1)), cfg, year=2026)
    assert result.malformed == {"malformed.line_too_long": 1}


def test_invalid_utf8_is_replaced_not_fatal(tmp_path, cfg):
    path = tmp_path / "auth.log"
    path.write_bytes(SSH.format(i=1).encode() + b"\n\xff\xfe broken\n")
    result = ingest_file(path, cfg, year=2026)
    assert len(result.events) == 1 and result.malformed_total == 1


@pytest.mark.parametrize(
    ("setup", "key"),
    [
        (lambda p: p / "missing.log", "error.file_not_found"),
        (lambda p: p, "error.not_a_file"),
    ],
)
def test_path_errors(tmp_path, cfg, setup, key):
    with pytest.raises(IngestionError) as err:
        ingest_file(setup(tmp_path), cfg)
    assert err.value.key == key


def test_file_too_large(tmp_path, cfg):
    cfg["ingestion"]["max_file_size_mb"] = 1
    path = write(tmp_path, "big.log", "x" * (2**20 + 1))
    with pytest.raises(IngestionError) as err:
        ingest_file(path, cfg)
    assert err.value.key == "error.file_too_large"


def test_binary_file_rejected(tmp_path, cfg):
    path = tmp_path / "image.log"
    path.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00")
    with pytest.raises(IngestionError) as err:
        ingest_file(path, cfg)
    assert err.value.key == "error.binary_file"


def test_bad_format_and_timezone(tmp_path, cfg):
    path = write(tmp_path, "auth.log", SSH.format(i=1))
    with pytest.raises(IngestionError) as err:
        ingest_file(path, cfg, fmt="evtx")
    assert err.value.key == "error.bad_format"
    with pytest.raises(IngestionError) as err:
        ingest_file(path, cfg, tz="Mars/Olympus")
    assert err.value.key == "error.bad_timezone"
