from pathlib import Path

import pytest

from logwarden.errors import IngestionError
from logwarden.sandbox import (
    MAX_UPLOAD_BYTES,
    analyze_upload,
    mask_ip,
    mask_params,
    mask_user,
)

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"


def test_analyze_ssh_sample(cfg):
    result = analyze_upload("auth.log", (SAMPLES / "auth.log").read_bytes(), cfg, 2026)
    assert result.ingest.fmt == "ssh"
    assert len(result.ingest.events) == 114
    assert {a.rule_id for a in result.alerts} >= {"LW-001", "LW-002"}


def test_analyze_webapp_sample(cfg):
    result = analyze_upload("app.jsonl", (SAMPLES / "app_auth.jsonl").read_bytes(), cfg, 2026)
    assert result.ingest.fmt == "webapp"
    assert "LW-003" in {a.rule_id for a in result.alerts}


def test_nothing_is_written_to_the_working_directory(cfg, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    analyze_upload("auth.log", (SAMPLES / "auth.log").read_bytes(), cfg, 2026)
    assert list(tmp_path.iterdir()) == []


def test_file_too_large(cfg):
    with pytest.raises(IngestionError) as err:
        analyze_upload("big.log", b"x" * (MAX_UPLOAD_BYTES + 1), cfg, 2026)
    assert err.value.key == "error.upload_too_large"


@pytest.mark.parametrize("name", ["evil.exe", "notes.pdf", "auth", "auth.log.sh"])
def test_extension_not_allowed(cfg, name):
    with pytest.raises(IngestionError) as err:
        analyze_upload(name, b"hello", cfg, 2026)
    assert err.value.key == "error.upload_bad_type"


def test_binary_content_rejected(cfg):
    with pytest.raises(IngestionError) as err:
        analyze_upload("auth.log", b"\x89PNG\x00\x00binary", cfg, 2026)
    assert err.value.key == "error.binary_file"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("192.0.2.10", "192.0.2.xxx"),
        ("2001:db8::1", "2001:0db8:xxxx"),
        (None, "-"),
        ("junk", "xxx"),
    ],
)
def test_mask_ip(value, expected):
    assert mask_ip(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"), [("alice", "a***e"), ("ab", "**"), ("root", "r***t"), (None, "-")]
)
def test_mask_user(value, expected):
    assert mask_user(value) == expected


def test_mask_params_keeps_counts_and_markers():
    params = {"ip": "203.0.113.5", "user": "alice", "users": ["bob", "carol", "(+3)"], "count": 7}
    masked = mask_params(params)
    assert masked == {
        "ip": "203.0.113.xxx",
        "user": "a***e",
        "users": ["b***b", "c***l", "(+3)"],
        "count": 7,
    }
    assert params["ip"] == "203.0.113.5"  # the original is not modified
