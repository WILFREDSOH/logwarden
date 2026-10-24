"""LogWarden local dashboard (Streamlit), bilingual EN/FR.

Launch with `logwarden dashboard` (binds to 127.0.0.1 only).
Security choices:
  * the database is opened read-only; the dashboard cannot modify data;
  * no file upload: ingestion stays a deliberate CLI action;
  * values coming from logs are attacker-controlled, so they are never rendered
    as Markdown/HTML (a crafted username could otherwise inject a link or an
    image that makes the browser contact an external server).
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import streamlit as st

from logwarden.config import load_config
from logwarden.dashboard import md_escape
from logwarden.errors import LogWardenError
from logwarden.i18n import SUPPORTED_LANGS, resolve_lang, t
from logwarden.models import Severity
from logwarden.reporting import charts, explain
from logwarden.reporting.stats import summarize
from logwarden.storage import Store

LANG_NAMES = {"en": "English", "fr": "Français"}


@st.cache_data(show_spinner=False)
def load_data(db_path: str, mtime: float) -> dict:
    """Read everything once per database version (`mtime` invalidates the cache)."""
    with Store(db_path, read_only=True) as store:
        return {
            "events": store.events(),
            "alerts": store.alerts(),
            "runs": store.ingestion_runs(),
            "anomalies": store.anomalies(),
        }


def sidebar() -> tuple[str, str]:
    default_lang = resolve_lang(os.environ.get("LOGWARDEN_LANG"))
    lang = st.sidebar.radio(
        "Language / Langue",
        SUPPORTED_LANGS,
        index=SUPPORTED_LANGS.index(default_lang),
        format_func=LANG_NAMES.get,
        horizontal=True,
    )
    db_path = os.environ.get("LOGWARDEN_DB", "logwarden.db")
    from logwarden import __version__

    st.sidebar.caption(f"LogWarden {__version__}")
    return lang, db_path


def overview(data: dict, lang: str) -> None:
    events, alerts = data["events"], data["alerts"]
    urgent = sum(1 for a in alerts if a.severity.rank >= Severity.HIGH.rank)
    c = st.columns(4)
    c[0].metric(t("report.events", lang), len(events))
    c[1].metric(t("report.alerts", lang), len(alerts))
    c[2].metric(t("ui.high_critical", lang), urgent)
    c[3].metric(t("report.unique_ips", lang), len({e.src_ip for e in events}))

    summary = summarize(events, alerts, data["runs"])
    left, right = st.columns(2)
    left.pyplot(charts.severity_figure(summary, lang))
    if summary.by_rule:
        right.pyplot(charts.rule_figure(summary, lang))
    if summary.hourly:
        st.pyplot(charts.timeline_figure(summary, lang))
    if summary.top_failure_ips:
        left, _ = st.columns(2)
        left.pyplot(charts.top_ips_figure(summary, lang))


def alerts_tab(data: dict, lang: str) -> None:
    alerts, by_id = data["alerts"], {e.event_id: e for e in data["events"]}
    if not alerts:
        st.info(t("report.no_alerts", lang))
        return
    c = st.columns([2, 2, 2])
    sev_filter = c[0].multiselect(
        t("label.severity", lang),
        [s.value for s in Severity],
        default=[s.value for s in Severity],
        format_func=lambda v: t(f"severity.{v}", lang),
    )
    rule_ids = sorted({a.rule_id for a in alerts})
    rule_filter = c[1].multiselect(t("label.rule", lang), rule_ids, default=rule_ids)
    query = c[2].text_input(t("ui.search_ip_user", lang)).strip().lower()
    shown = [
        a
        for a in alerts
        if a.severity.value in sev_filter
        and a.rule_id in rule_filter
        and (not query or query in (a.src_ip or "").lower() or query in (a.username or "").lower())
    ]
    table = pd.DataFrame(
        [
            {
                t("label.severity", lang): t(f"severity.{a.severity.value}", lang),
                t("label.score", lang): a.score,
                t("label.rule", lang): f"{a.rule_id} {t(f'rule.{a.rule_id}.name', lang)}",
                t("label.ip", lang): a.src_ip or "-",
                t("label.user", lang): a.username or "-",
                t("label.first_seen", lang): a.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
                t("label.events", lang): len(a.event_ids),
            }
            for a in shown
        ]
    )
    st.caption(t("ui.shown", lang, n=len(shown), total=len(alerts)))
    st.dataframe(table, hide_index=True, width="stretch")
    if not shown:
        return

    st.subheader(t("report.alert_details", lang))
    labels = {
        a.alert_id: f"[{t(f'severity.{a.severity.value}', lang).upper()} {a.score}] {a.rule_id} · "
        f"{a.src_ip or '-'} · {a.username or '-'} · {a.first_seen:%m-%d %H:%M}"
        for a in shown
    }
    chosen = st.selectbox(t("ui.pick_alert", lang), list(labels), format_func=labels.get)
    alert = next(a for a in shown if a.alert_id == chosen)
    st.markdown(
        f"**{md_escape(t(f'rule.{alert.rule_id}.name', lang))}** — "
        f"{md_escape(t(f'rule.{alert.rule_id}.description', lang))}"
    )
    box = {
        Severity.CRITICAL: st.error,
        Severity.HIGH: st.error,
        Severity.MEDIUM: st.warning,
        Severity.LOW: st.info,
    }[alert.severity]
    box(md_escape(explain(alert, lang)))
    left, right = st.columns([1, 2])
    with left:
        st.markdown(f"**{t('label.score_breakdown', lang)}**")
        st.dataframe(
            pd.DataFrame(
                [
                    {t("ui.factor", lang): t(i.label_key, lang), t("ui.points", lang): i.points}
                    for i in alert.score_breakdown
                ]
                + [{t("ui.factor", lang): t("ui.total", lang), t("ui.points", lang): alert.score}]
            ),
            hide_index=True,
            width="stretch",
        )
    with right:
        st.markdown(f"**{t('label.recommendation', lang)}**")
        st.write(t(f"rule.{alert.rule_id}.action", lang))
    st.markdown(f"**{t('ui.evidence', lang, n=len(alert.event_ids))}**")
    evidence = [by_id[eid] for eid in alert.event_ids if eid in by_id]
    st.dataframe(_events_frame(evidence, lang), hide_index=True, width="stretch")


def _events_frame(events: list, lang: str) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                t("label.time", lang): e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                t("label.source", lang): e.source,
                t("label.type", lang): t(f"event_type.{e.event_type.value}", lang),
                t("label.user", lang): e.username or "-",
                t("label.ip", lang): e.src_ip or "-",
                t("label.raw", lang): e.raw,
            }
            for e in events
        ]
    )


def events_tab(data: dict, lang: str) -> None:
    events = data["events"]
    c = st.columns(3)
    types = sorted({e.event_type.value for e in events})
    type_filter = c[0].multiselect(
        t("label.type", lang),
        types,
        default=types,
        format_func=lambda v: t(f"event_type.{v}", lang),
    )
    sources = sorted({e.source for e in events})
    source_filter = c[1].multiselect(t("label.source", lang), sources, default=sources)
    query = c[2].text_input(t("ui.search_ip_user", lang), key="ev_q").strip().lower()
    shown = [
        e
        for e in events
        if e.event_type.value in type_filter
        and e.source in source_filter
        and (not query or query in (e.src_ip or "").lower() or query in (e.username or "").lower())
    ]
    st.caption(t("ui.shown", lang, n=min(len(shown), 5000), total=len(events)))
    st.dataframe(_events_frame(shown[:5000], lang), hide_index=True, width="stretch")


def anomalies_tab(data: dict, lang: str, window_minutes: int) -> None:
    rows, alerts = data["anomalies"], data["alerts"]
    st.caption(t("ui.ml_explainer", lang))
    if not rows:
        st.info(t("ui.ml_none", lang))
        return
    flagged = [r for r in rows if r["is_anomaly"]]
    c = st.columns(3)
    c[0].metric(t("ui.windows", lang), len(rows))
    c[1].metric(t("ui.anomalies", lang), len(flagged))
    c[2].metric(t("ui.threshold", lang), rows[0]["threshold"])

    def rules_cover(row: dict) -> bool:
        start = datetime.fromisoformat(row["window_start"])
        end = start + timedelta(minutes=window_minutes)
        return any(
            a.src_ip == row["src_ip"] and a.first_seen <= end and start <= a.last_seen
            for a in alerts
        )

    yes, no = t("label.yes", lang), t("label.no", lang)
    st.subheader(t("ui.ml_vs_rules", lang))
    st.dataframe(
        pd.DataFrame(
            [
                {
                    t("label.ip", lang): r["src_ip"],
                    t("label.window", lang): r["window_start"][:16].replace("T", " "),
                    t("label.anomaly_score", lang): r["score"],
                    t("ui.rules_alerted", lang): yes if rules_cover(r) else no,
                    t("label.top_features", lang): "; ".join(
                        f"{t(f'feature.{f}', lang)}={v} ({t('label.median', lang)} {m})"
                        for f, v, m in r["top_features"]
                    ),
                }
                for r in flagged
            ]
        ),
        hide_index=True,
        width="stretch",
    )

    st.subheader(t("ui.score_distribution", lang))
    scores = pd.DataFrame({"score": [r["score"] for r in rows]})
    st.bar_chart(scores["score"].round(2).value_counts().sort_index())


def quality_tab(data: dict, lang: str) -> None:
    st.caption(t("report.quality_intro", lang))
    runs = data["runs"]
    if not runs:
        st.info(t("ui.no_runs", lang))
        return
    st.dataframe(
        pd.DataFrame(
            [
                {
                    t("report.files", lang): Path(r.path).name,
                    t("ui.format", lang): r.fmt,
                    t("report.lines_total", lang): r.total_lines,
                    t("ui.new_events", lang): r.new_events,
                    t("report.lines_skipped", lang): r.skipped,
                    t("report.duplicates", lang): r.duplicates,
                    t("ui.malformed", lang): r.malformed,
                    t("ui.details", lang): ", ".join(
                        f"{t(k, lang)}: {v}" for k, v in r.malformed_detail.items()
                    ),
                    t("ui.ingested_at", lang): r.started_at[:19].replace("T", " "),
                }
                for r in runs
            ]
        ),
        hide_index=True,
        width="stretch",
    )


def main() -> None:
    st.set_page_config(page_title="LogWarden", page_icon="🛡️", layout="wide")
    lang, db_path = sidebar()
    st.title(t("ui.title", lang))
    st.caption(t("ui.subtitle", lang))
    try:
        cfg = load_config(os.environ.get("LOGWARDEN_CONFIG"))
        data = load_data(db_path, Path(db_path).stat().st_mtime if Path(db_path).exists() else 0.0)
    except LogWardenError as exc:
        st.error(md_escape(exc.localized(lang)))
        st.stop()
        return
    tabs = st.tabs(
        [
            t("ui.tab_overview", lang),
            t("ui.tab_alerts", lang),
            t("ui.tab_events", lang),
            t("ui.tab_ml", lang),
            t("ui.tab_quality", lang),
        ]
    )
    with tabs[0]:
        overview(data, lang)
    with tabs[1]:
        alerts_tab(data, lang)
    with tabs[2]:
        events_tab(data, lang)
    with tabs[3]:
        anomalies_tab(data, lang, cfg["ml"]["window_minutes"])
    with tabs[4]:
        quality_tab(data, lang)


if __name__ == "__main__":
    main()
