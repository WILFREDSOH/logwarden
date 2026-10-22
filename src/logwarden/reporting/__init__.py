"""Rendering of alerts for humans: explanations, exports, reports."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from logwarden.i18n import t
from logwarden.models import Alert

ALERT_FIELDS = (
    "alert_id",
    "rule_id",
    "rule",
    "severity",
    "severity_label",
    "score",
    "first_seen",
    "last_seen",
    "username",
    "src_ip",
    "event_count",
    "explanation",
    "score_breakdown",
)


def explain(alert: Alert, lang: str) -> str:
    return t(alert.explanation_key, lang, **alert.explanation_params)


def score_text(alert: Alert, lang: str) -> str:
    parts = [f"{t(item.label_key, lang)} {item.points:+d}" for item in alert.score_breakdown]
    return " ; ".join(parts) + f" = {alert.score}"


def _csv_safe(value: object) -> object:
    """Neutralise spreadsheet formulas (CSV injection): log fields are attacker-controlled."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def alert_record(alert: Alert, lang: str) -> dict[str, object]:
    return {
        "alert_id": alert.alert_id,
        "rule_id": alert.rule_id,
        "rule": t(f"rule.{alert.rule_id}.name", lang),
        "severity": alert.severity.value,
        "severity_label": t(f"severity.{alert.severity.value}", lang),
        "score": alert.score,
        "first_seen": alert.first_seen.isoformat(),
        "last_seen": alert.last_seen.isoformat(),
        "username": alert.username or "",
        "src_ip": alert.src_ip or "",
        "event_count": len(alert.event_ids),
        "explanation": explain(alert, lang),
        "score_breakdown": score_text(alert, lang),
    }


def export_alerts(alerts: list[Alert], lang: str, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    records = [alert_record(a, lang) for a in alerts]
    json_path = out_dir / f"alerts.{lang}.json"
    json_path.write_text(json.dumps(records, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    csv_path = out_dir / f"alerts.{lang}.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=ALERT_FIELDS)
        writer.writeheader()
        for rec in records:
            writer.writerow({k: _csv_safe(v) for k, v in rec.items()})
    return json_path, csv_path
