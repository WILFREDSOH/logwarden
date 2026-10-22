"""Markdown report (readable on GitHub, in VS Code, or converted to PDF)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from logwarden import __version__
from logwarden.evaluation import Evaluation
from logwarden.i18n import t
from logwarden.models import Alert, Event, Severity
from logwarden.reporting import explain, score_text
from logwarden.reporting.stats import Summary

MAX_DETAILED = 20
MAX_EVIDENCE = 6


def _cell(value: object) -> str:
    """Make a value safe inside a Markdown table cell."""
    text = "" if value is None else str(value)
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _table(headers: list[str], rows: list[list[object]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows]
    return "\n".join(out)


def _ts(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "-"


def _pct(value: float | None) -> str:
    return "-" if value is None else f"{value:.0%}"


def build_report(
    summary: Summary,
    alerts: list[Alert],
    evidence: dict[str, list[Event]],
    lang: str,
    charts: dict[str, str],
    anomalies: list[dict[str, Any]] | None = None,
    evaluation: Evaluation | None = None,
) -> str:
    L: list[str] = []
    add = L.append
    add(f"# {t('report.title', lang)}\n")
    add(t("report.generated", lang, date=_ts(datetime.now(UTC)), version=__version__) + "\n")
    add(f"> {t('report.disclaimer', lang)}\n")

    # 1. Summary
    add(f"## 1. {t('report.summary', lang)}\n")
    sev = summary.by_severity
    add(
        _table(
            [t("report.metric", lang), t("report.value", lang)],
            [
                [
                    t("report.period", lang),
                    f"{_ts(summary.first_event)} → {_ts(summary.last_event)}",
                ],
                [t("report.events", lang), summary.events_total],
                *[[f"  {t(f'event_type.{k}', lang)}", v] for k, v in summary.by_type.items()],
                [
                    t("report.sources", lang),
                    ", ".join(f"{k}: {v}" for k, v in summary.by_source.items()),
                ],
                [t("report.unique_ips", lang), summary.unique_ips],
                [t("report.unique_users", lang), summary.unique_users],
                [t("report.alerts", lang), summary.alerts_total],
                *[[f"  {t(f'severity.{k}', lang)}", sev[k]] for k in reversed(list(sev))],
            ],
        )
        + "\n"
    )

    # 2. Data quality
    add(f"## 2. {t('report.quality', lang)}\n")
    add(t("report.quality_intro", lang) + "\n")
    rows: list[list[object]] = [
        [t("report.files", lang), ", ".join(Path(f).name for f in summary.files)],
        [t("report.lines_total", lang), summary.lines_total],
        [t("report.lines_skipped", lang), summary.lines_skipped],
        [t("report.duplicates", lang), summary.duplicates],
    ]
    rows += [[t(reason, lang), count] for reason, count in summary.malformed.items()]
    add(_table([t("report.metric", lang), t("report.value", lang)], rows) + "\n")

    # 3. Alerts
    add(f"## 3. {t('report.alerts', lang)}\n")
    for key in ("severity", "rule"):
        if key in charts:
            add(f"![{t(f'chart.alerts_by_{key}', lang)}]({charts[key]})\n")
    if not alerts:
        add(t("report.no_alerts", lang) + "\n")
    else:
        add(
            _table(
                [
                    "#",
                    t("label.severity", lang),
                    t("label.score", lang),
                    t("label.rule", lang),
                    t("label.ip", lang),
                    t("label.user", lang),
                    t("label.first_seen", lang),
                    t("label.events", lang),
                ],
                [
                    [
                        i,
                        t(f"severity.{a.severity.value}", lang).upper(),
                        a.score,
                        f"{a.rule_id} {t(f'rule.{a.rule_id}.name', lang)}",
                        a.src_ip or "-",
                        a.username or "-",
                        _ts(a.first_seen),
                        len(a.event_ids),
                    ]
                    for i, a in enumerate(alerts, 1)
                ],
            )
            + "\n"
        )

        add(f"### {t('report.alert_details', lang)}\n")
        detailed = [a for a in alerts if a.severity.rank >= Severity.MEDIUM.rank][:MAX_DETAILED]
        for i, a in enumerate(detailed, 1):
            add(
                f"#### {i}. [{t(f'severity.{a.severity.value}', lang).upper()} {a.score}] "
                f"{a.rule_id} — {t(f'rule.{a.rule_id}.name', lang)}\n"
            )
            add(f"- **{t('label.explanation', lang)}** — {explain(a, lang)}")
            add(f"- **{t('label.score_breakdown', lang)}** — {score_text(a, lang)}")
            add(f"- **{t('label.period', lang)}** — {_ts(a.first_seen)} → {_ts(a.last_seen)}")
            add(
                f"- **{t('label.recommendation', lang)}** — {t(f'rule.{a.rule_id}.action', lang)}\n"
            )
            events = evidence.get(a.alert_id, [])
            if events:
                add(
                    t(
                        "report.evidence",
                        lang,
                        shown=min(len(events), MAX_EVIDENCE),
                        total=len(a.event_ids),
                    )
                )
                add("```text")
                add("\n".join(e.raw.replace("`", "'") for e in events[:MAX_EVIDENCE]))
                add("```\n")

    # 4. Activity
    add(f"## 4. {t('report.activity', lang)}\n")
    if "timeline" in charts:
        add(f"![{t('chart.timeline', lang)}]({charts['timeline']})\n")
    if "top_ips" in charts:
        add(f"![{t('chart.top_ips', lang)}]({charts['top_ips']})\n")
    if summary.top_targeted_users:
        add(f"**{t('report.top_users', lang)}**\n")
        add(
            _table(
                [t("label.user", lang), t("chart.failures", lang)],
                [list(r) for r in summary.top_targeted_users],
            )
            + "\n"
        )

    # 5. Anomaly detection (optional)
    if anomalies:
        flagged = [r for r in anomalies if r["is_anomaly"]]
        add(f"## 5. {t('report.ml', lang)}\n")
        add(
            t(
                "report.ml_intro",
                lang,
                windows=len(anomalies),
                flagged=len(flagged),
                threshold=anomalies[0]["threshold"],
            )
            + "\n"
        )
        if flagged:
            add(
                _table(
                    [
                        t("label.ip", lang),
                        t("label.window", lang),
                        t("label.anomaly_score", lang),
                        t("label.top_features", lang),
                    ],
                    [
                        [
                            r["src_ip"],
                            r["window_start"][:16].replace("T", " "),
                            r["score"],
                            "; ".join(
                                f"{t(f'feature.{f}', lang)}={v} ({t('label.median', lang)} {m})"
                                for f, v, m in r["top_features"]
                            ),
                        ]
                        for r in flagged
                    ],
                )
                + "\n"
            )

    # 6. Evaluation against ground truth (synthetic data only)
    if evaluation is not None:
        add(f"## 6. {t('report.evaluation', lang)}\n")
        add(f"> {t('report.evaluation_warning', lang)}\n")
        yes, no = t("label.yes", lang), t("label.no", lang)
        add(
            _table(
                [
                    t("label.scenario", lang),
                    t("label.ip", lang),
                    t("label.expected_rules", lang),
                    t("label.rules_fired", lang),
                    t("label.rules_ok", lang),
                    t("label.ml_flagged", lang),
                ],
                [
                    [
                        r.scenario.name,
                        r.scenario.src_ip,
                        ", ".join(r.scenario.expected_rules) or "-",
                        ", ".join(r.rules_fired) or "-",
                        "-" if not r.scenario.expected_rules else (yes if r.expected_ok else no),
                        "-" if r.ml_flagged is None else (yes if r.ml_flagged else no),
                    ]
                    for r in evaluation.scenarios
                ],
            )
            + "\n"
        )
        add(t("report.alerts_outside", lang, n=evaluation.alerts_outside_scenarios) + "\n")
        if evaluation.windows:
            add(
                _table(
                    [
                        t("label.detector", lang),
                        "TP",
                        "FP",
                        "FN",
                        "TN",
                        t("label.precision", lang),
                        t("label.recall", lang),
                    ],
                    [
                        [
                            t(f"detector.{name}", lang),
                            c.tp,
                            c.fp,
                            c.fn,
                            c.tn,
                            _pct(c.precision),
                            _pct(c.recall),
                        ]
                        for name, c in evaluation.windows.items()
                    ],
                )
                + "\n"
            )

    add("---\n")
    add(t("report.footer", lang) + "\n")
    return "\n".join(L)
