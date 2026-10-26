"""Sandbox mode: analyse a visitor's uploaded log file without storing anything.

The upload is validated (size, extension, text), written to a temporary
directory that is deleted right after parsing, and analysed in memory. No
database is created and nothing outlives the request. Display helpers mask IP
addresses and account names, because visitors may upload real data by mistake.
"""

from __future__ import annotations

import ipaddress
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from logwarden.detection import run_detection
from logwarden.errors import IngestionError
from logwarden.ingestion import IngestResult, ingest_file
from logwarden.models import Alert

MAX_UPLOAD_BYTES = 2 * 1024 * 1024
ALLOWED_SUFFIXES = (".log", ".txt", ".jsonl")


@dataclass
class SandboxResult:
    ingest: IngestResult
    alerts: list[Alert] = field(default_factory=list)


def analyze_upload(name: str, data: bytes, cfg: dict[str, Any], year: int) -> SandboxResult:
    if len(data) > MAX_UPLOAD_BYTES:
        raise IngestionError("error.upload_too_large", max_mb=MAX_UPLOAD_BYTES // 2**20)
    suffix = Path(name).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise IngestionError("error.upload_bad_type", allowed=", ".join(ALLOWED_SUFFIXES))
    with tempfile.TemporaryDirectory(prefix="logwarden-sandbox-") as tmp:
        path = Path(tmp) / f"upload{suffix}"  # never reuse the visitor's file name
        path.write_bytes(data)
        result = ingest_file(path, cfg, year=year)
    return SandboxResult(ingest=result, alerts=run_detection(result.events, cfg))


def mask_ip(value: str | None) -> str:
    """192.0.2.10 -> 192.0.2.xxx ; 2001:db8::1 -> 2001:0db8:xxxx."""
    if not value:
        return "-"
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "xxx"
    if ip.version == 4:
        return ".".join(value.split(".")[:3] + ["xxx"])
    return ":".join(ip.exploded.split(":")[:2] + ["xxxx"])


def mask_user(value: str | None) -> str:
    """alice -> a***e ; ab -> **."""
    if not value:
        return "-"
    if len(value) <= 2:
        return "*" * len(value)
    return f"{value[0]}***{value[-1]}"


_IP_KEYS = {"ip"}
_IP_LIST_KEYS = {"ips"}
_USER_KEYS = {"user"}
_USER_LIST_KEYS = {"users", "invalid_users", "success_users"}


def _mask_list(values: Any, masker: Any) -> Any:
    if not isinstance(values, list):
        return values
    # keep markers such as "-" or "(+3)" readable
    return [v if v == "-" or str(v).startswith("(+") else masker(v) for v in values]


def mask_params(params: dict[str, Any]) -> dict[str, Any]:
    """Mask the IPs and account names inside an alert's explanation parameters."""
    masked = dict(params)
    for key, value in params.items():
        if key in _IP_KEYS:
            masked[key] = mask_ip(value)
        elif key in _USER_KEYS:
            masked[key] = mask_user(value)
        elif key in _IP_LIST_KEYS:
            masked[key] = _mask_list(value, mask_ip)
        elif key in _USER_LIST_KEYS:
            masked[key] = _mask_list(value, mask_user)
    return masked
