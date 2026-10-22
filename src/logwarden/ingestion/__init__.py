"""File ingestion: validate a log file, parse each line, normalise and de-duplicate.

A bad line never stops ingestion: it is counted (with its reason) so data
quality problems are visible in the report instead of being silently ignored.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from logwarden.errors import IngestionError
from logwarden.ingestion.common import Malformed, Skip
from logwarden.ingestion.ssh import SshParser
from logwarden.ingestion.webapp import WebAppParser
from logwarden.models import Event

FORMATS = ("auto", "ssh", "webapp")
MAX_ERRORS_KEPT = 50


@dataclass
class IngestResult:
    path: str
    fmt: str
    events: list[Event] = field(default_factory=list)
    total_lines: int = 0
    blank_lines: int = 0
    skipped: int = 0
    duplicates: int = 0
    malformed: Counter[str] = field(default_factory=Counter)
    errors: list[tuple[int, str]] = field(default_factory=list)  # (line number, reason key)

    @property
    def malformed_total(self) -> int:
        return sum(self.malformed.values())


def detect_format(path: Path, first_line: str) -> str:
    if path.suffix.lower() in (".jsonl", ".json", ".ndjson"):
        return "webapp"
    return "webapp" if first_line.lstrip().startswith("{") else "ssh"


def get_timezone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise IngestionError("error.bad_timezone", tz=name) from exc


def _check_file(path: Path, max_bytes: int) -> None:
    if not path.exists():
        raise IngestionError("error.file_not_found", path=str(path))
    if not path.is_file():
        raise IngestionError("error.not_a_file", path=str(path))
    size = path.stat().st_size
    if size > max_bytes:
        raise IngestionError(
            "error.file_too_large",
            path=str(path),
            size_mb=round(size / 2**20, 1),
            max_mb=max_bytes // 2**20,
        )
    with path.open("rb") as fh:
        if b"\x00" in fh.read(8192):
            raise IngestionError("error.binary_file", path=str(path))


def ingest_file(
    path: str | Path,
    cfg: dict[str, Any],
    fmt: str = "auto",
    year: int | None = None,
    tz: str = "UTC",
    seen_ids: set[str] | None = None,
) -> IngestResult:
    """Parse `path` into normalised events.

    `seen_ids` lets the caller de-duplicate across several files; it is updated in place.
    """
    if fmt not in FORMATS:
        raise IngestionError("error.bad_format", fmt=fmt, choices=", ".join(FORMATS))
    path = Path(path)
    icfg = cfg["ingestion"]
    _check_file(path, icfg["max_file_size_mb"] * 2**20)
    seen = seen_ids if seen_ids is not None else set()

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise IngestionError("error.file_unreadable", path=str(path), detail=exc.strerror) from exc

    first = next((ln for ln in lines if ln.strip()), "")
    if fmt == "auto":
        fmt = detect_format(path, first)
    parser: SshParser | WebAppParser
    if fmt == "ssh":
        parser = SshParser(year or datetime.now(UTC).year, get_timezone(tz), icfg["raw_max_chars"])
    else:
        parser = WebAppParser(icfg["redacted_fields"], icfg["raw_max_chars"])

    result = IngestResult(path=str(path), fmt=fmt, total_lines=len(lines))
    for line_no, line in enumerate(lines, 1):
        if not line.strip():
            result.blank_lines += 1
            continue
        if len(line) > icfg["max_line_length"]:
            outcome: Event | Skip | Malformed = Malformed("malformed.line_too_long")
        else:
            outcome = parser.parse_line(line)

        if isinstance(outcome, Malformed):
            result.malformed[outcome.reason] += 1
            if len(result.errors) < MAX_ERRORS_KEPT:
                result.errors.append((line_no, outcome.reason))
        elif isinstance(outcome, Skip):
            result.skipped += 1
        elif outcome.event_id in seen:
            result.duplicates += 1
        else:
            seen.add(outcome.event_id)
            result.events.append(outcome)
    return result
