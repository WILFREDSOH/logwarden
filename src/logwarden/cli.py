"""Command-line interface: `logwarden <command> [options]` (also `python -m logwarden`)."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from logwarden import __version__
from logwarden.config import load_config
from logwarden.detection import run_detection
from logwarden.errors import LogWardenError
from logwarden.i18n import SUPPORTED_LANGS, resolve_lang, t
from logwarden.ingestion import FORMATS, ingest_file
from logwarden.models import Severity
from logwarden.storage import IngestionRun, Store

DEFAULT_DB = "logwarden.db"
DEMO_DIR = Path("data/generated")
DEMO_DB = DEMO_DIR / "demo.db"
BASELINE = {"seed": 7, "start": date(2026, 9, 28), "days": 14}


def _out(msg: str = "") -> None:
    print(msg, flush=True)


def _db_path(args: argparse.Namespace) -> Path:
    return Path(args.db or os.environ.get("LOGWARDEN_DB") or DEFAULT_DB)


# ---- commands ---------------------------------------------------------------


def cmd_generate(args: argparse.Namespace, cfg: dict[str, Any], lang: str) -> int:
    from logwarden.synth import generate

    if args.baseline:
        paths, _ = generate(
            args.out or DEMO_DIR / "baseline",
            seed=args.seed or BASELINE["seed"],
            start=BASELINE["start"],
            days=BASELINE["days"],
            attacks=False,
            quality_issues=False,
        )
    else:
        paths, _ = generate(args.out or DEMO_DIR / "demo", seed=args.seed or 42)
    for p in paths:
        _out(t("cli.generated", lang, path=str(p)))
    return 0


def ingest_paths(
    store: Store,
    paths: list[str],
    cfg: dict[str, Any],
    lang: str,
    fmt: str = "auto",
    year: int | None = None,
    tz: str = "UTC",
) -> int:
    seen: set[str] = set()
    total_new = 0
    for path in paths:
        started = datetime.now(UTC).isoformat()
        result = ingest_file(path, cfg, fmt=fmt, year=year, tz=tz, seen_ids=seen)
        new = store.add_events(result.events)
        already = len(result.events) - new  # present in the database from a previous run
        store.record_run(
            IngestionRun(
                started_at=started,
                path=str(path),
                fmt=result.fmt,
                total_lines=result.total_lines,
                new_events=new,
                skipped=result.skipped + result.blank_lines,
                duplicates=result.duplicates + already,
                malformed=result.malformed_total,
                malformed_detail=dict(result.malformed),
            )
        )
        total_new += new
        _out(
            t(
                "cli.ingested",
                lang,
                file=Path(path).name,
                fmt=result.fmt,
                lines=result.total_lines,
                new=new,
                skipped=result.skipped + result.blank_lines,
                duplicates=result.duplicates + already,
                malformed=result.malformed_total,
            )
        )
        for line_no, reason in result.errors[:5]:
            _out("   " + t("cli.malformed_line", lang, line=line_no, reason=t(reason, lang)))
    return total_new


def cmd_ingest(args: argparse.Namespace, cfg: dict[str, Any], lang: str) -> int:
    with Store(_db_path(args)) as store:
        ingest_paths(store, args.files, cfg, lang, args.format, args.year, args.tz)
        _out(t("cli.db_counts", lang, path=str(store.path), **store.counts()))
    return 0


def detect_into(store: Store, cfg: dict[str, Any], lang: str) -> list:
    events = store.events()
    if not events:
        raise LogWardenError("error.no_events")
    alerts = run_detection(events, cfg)
    store.replace_alerts(alerts)
    by_sev = {s: sum(1 for a in alerts if a.severity is s) for s in Severity}
    _out(
        t(
            "cli.detected",
            lang,
            events=len(events),
            alerts=len(alerts),
            detail=", ".join(f"{t(f'severity.{s.value}', lang)}: {n}" for s, n in by_sev.items()),
        )
    )
    return alerts


def cmd_detect(args: argparse.Namespace, cfg: dict[str, Any], lang: str) -> int:
    with Store(_db_path(args)) as store:
        detect_into(store, cfg, lang)
    return 0


def anomalies_into(
    store: Store, cfg: dict[str, Any], lang: str, baseline_files: list[str] | None, year: int | None
) -> list[dict[str, Any]]:
    from logwarden.ml import score_anomalies

    baseline = None
    if baseline_files:
        seen: set[str] = set()
        baseline = []
        for path in baseline_files:
            baseline += ingest_file(path, cfg, year=year, seen_ids=seen).events
    rows = score_anomalies(store.events(), baseline, cfg)
    store.replace_anomalies(rows)
    flagged = sum(1 for r in rows if r["is_anomaly"])
    mode = t("cli.ml_mode_baseline" if baseline else "cli.ml_mode_self", lang)
    _out(t("cli.ml_done", lang, windows=len(rows), flagged=flagged, mode=mode))
    return rows


def cmd_anomalies(args: argparse.Namespace, cfg: dict[str, Any], lang: str) -> int:
    with Store(_db_path(args)) as store:
        anomalies_into(store, cfg, lang, args.baseline, args.year)
    return 0


def write_report(
    store: Store,
    cfg: dict[str, Any],
    lang: str,
    out_dir: Path,
    ground_truth: str | None = None,
    msg_lang: str | None = None,
) -> Path:
    from logwarden.evaluation import evaluate
    from logwarden.reporting import export_alerts
    from logwarden.reporting.charts import render_all
    from logwarden.reporting.markdown import build_report
    from logwarden.reporting.stats import summarize
    from logwarden.synth import GroundTruth

    events, alerts, anomalies = store.events(), store.alerts(), store.anomalies()
    summary = summarize(events, alerts, store.ingestion_runs())
    chart_paths = render_all(summary, lang, out_dir / "charts" / lang)
    names = {
        "alerts_by_severity": "severity",
        "alerts_by_rule": "rule",
        "timeline": "timeline",
        "top_failure_ips": "top_ips",
    }
    charts = {names[p.stem]: f"charts/{lang}/{p.name}" for p in chart_paths}
    evidence = {a.alert_id: store.events_by_ids(a.event_ids[:6]) for a in alerts}
    evaluation = None
    if ground_truth:
        try:
            gt = GroundTruth.load(ground_truth)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise LogWardenError("error.ground_truth", path=ground_truth, detail=str(exc)) from exc
        evaluation = evaluate(gt, alerts, anomalies, cfg["ml"]["window_minutes"])
    text = build_report(summary, alerts, evidence, lang, charts, anomalies, evaluation)
    out_dir.mkdir(parents=True, exist_ok=True)
    report = out_dir / f"report.{lang}.md"
    report.write_text(text, encoding="utf-8")
    export_alerts(alerts, lang, out_dir)
    _out(t("cli.report_written", msg_lang or lang, path=str(report)))
    return report


def cmd_report(args: argparse.Namespace, cfg: dict[str, Any], lang: str) -> int:
    with Store(_db_path(args), read_only=True) as store:
        write_report(store, cfg, lang, Path(args.out), args.ground_truth)
    return 0


def cmd_alerts(args: argparse.Namespace, cfg: dict[str, Any], lang: str) -> int:
    from logwarden.reporting import explain

    with Store(_db_path(args), read_only=True) as store:
        alerts = [a for a in store.alerts() if a.severity.rank >= Severity(args.min_severity).rank]
    if not alerts:
        _out(t("report.no_alerts", lang))
    for a in alerts[: args.limit]:
        _out(
            f"[{t(f'severity.{a.severity.value}', lang).upper():>8} {a.score:>3}] {a.rule_id} "
            f"{t(f'rule.{a.rule_id}.name', lang)} | {a.src_ip or '-'} | {a.username or '-'} | "
            f"{a.first_seen:%Y-%m-%d %H:%M}"
        )
        _out(f"    {explain(a, lang)}")
    return 0


def cmd_demo(args: argparse.Namespace, cfg: dict[str, Any], lang: str) -> int:
    """Regenerate the synthetic data and run the whole pipeline end to end."""
    from logwarden.synth import generate

    data_dir = Path(args.data_dir)
    demo_paths, gt = generate(data_dir / "demo", seed=args.seed)
    base_paths, _ = generate(
        data_dir / "baseline",
        seed=BASELINE["seed"],
        start=BASELINE["start"],
        days=BASELINE["days"],
        attacks=False,
        quality_issues=False,
    )
    db = data_dir / "demo.db"
    db.unlink(missing_ok=True)  # the demo database is always rebuilt from scratch
    _out(t("cli.demo_step", lang, step=1, text=t("cli.demo_generate", lang, path=str(data_dir))))
    with Store(db) as store:
        _out(t("cli.demo_step", lang, step=2, text=t("cli.demo_ingest", lang)))
        ingest_paths(store, [str(p) for p in demo_paths[:2]], cfg, lang, year=gt.year)
        _out(t("cli.demo_step", lang, step=3, text=t("cli.demo_detect", lang)))
        detect_into(store, cfg, lang)
        if not args.no_ml:
            _out(t("cli.demo_step", lang, step=4, text=t("cli.demo_ml", lang)))
            try:
                anomalies_into(store, cfg, lang, [str(p) for p in base_paths[:2]], gt.year)
            except LogWardenError as exc:
                if exc.key != "error.ml_missing":
                    raise
                _out("   " + exc.localized(lang))
        _out(t("cli.demo_step", lang, step=5, text=t("cli.demo_report", lang)))
        for report_lang in SUPPORTED_LANGS:
            write_report(store, cfg, report_lang, Path(args.out), str(demo_paths[2]), lang)
    _out("")
    _out(t("cli.demo_done", lang, db=str(db), out=args.out))
    return 0


def cmd_dashboard(args: argparse.Namespace, cfg: dict[str, Any], lang: str) -> int:
    if shutil.which("streamlit") is None:
        try:
            import streamlit  # noqa: F401
        except ImportError as exc:
            raise LogWardenError("error.dashboard_missing") from exc
    db = _db_path(args)
    if not db.exists() and args.db is None and DEMO_DB.exists():
        db = DEMO_DB
        _out(t("cli.dashboard_demo_db", lang, path=str(db)))
    if not db.exists():
        raise LogWardenError("error.db_not_found", path=str(db))
    app = Path(__file__).parent / "dashboard" / "app.py"
    env = {**os.environ, "LOGWARDEN_DB": str(db.resolve()), "LOGWARDEN_LANG": lang}
    if args.config:
        env["LOGWARDEN_CONFIG"] = str(Path(args.config).resolve())
    _out(t("cli.dashboard_url", lang, port=args.port))
    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(app),
        "--server.address",
        "127.0.0.1",
        "--server.port",
        str(args.port),
        "--server.headless",
        "true",
        "--browser.gatherUsageStats",
        "false",
    ]
    return subprocess.call(cmd, env=env)  # noqa: S603 - fixed argument list, no shell


# ---- parser -----------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--lang",
        choices=SUPPORTED_LANGS,
        default=argparse.SUPPRESS,
        help="output language / langue (en, fr). Default: $LOGWARDEN_LANG or en",
    )
    common.add_argument(
        "--db",
        default=argparse.SUPPRESS,
        help=f"SQLite database path (default: $LOGWARDEN_DB or {DEFAULT_DB})",
    )
    common.add_argument("--config", default=argparse.SUPPRESS, help="TOML file overriding defaults")

    parser = argparse.ArgumentParser(
        prog="logwarden",
        parents=[common],
        description="LogWarden - explainable detection of suspicious authentication activity.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p = sub.add_parser("demo", parents=[common], help="generate data and run the full pipeline")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--data-dir", default=str(DEMO_DIR))
    p.add_argument("--out", default="reports/demo", help="report directory")
    p.add_argument("--no-ml", action="store_true", help="skip anomaly detection")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("generate", parents=[common], help="write synthetic log files")
    p.add_argument("--out", type=Path)
    p.add_argument("--seed", type=int)
    p.add_argument("--baseline", action="store_true", help="normal activity only (ML training)")
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("ingest", parents=[common], help="import log files into the database")
    p.add_argument("files", nargs="+")
    p.add_argument("--format", choices=FORMATS, default="auto")
    p.add_argument(
        "--year", type=int, help="year of traditional syslog timestamps (default: current)"
    )
    p.add_argument("--tz", default="UTC", help="timezone of traditional syslog timestamps")
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("detect", parents=[common], help="run detection rules, store alerts")
    p.set_defaults(func=cmd_detect)

    p = sub.add_parser("anomalies", parents=[common], help="score IP/time windows (scikit-learn)")
    p.add_argument("--baseline", nargs="+", metavar="FILE", help="log files of normal activity")
    p.add_argument("--year", type=int)
    p.set_defaults(func=cmd_anomalies)

    p = sub.add_parser("report", parents=[common], help="write Markdown report, charts, CSV/JSON")
    p.add_argument("--out", default="reports/latest")
    p.add_argument("--ground-truth", help="ground_truth.json of a synthetic dataset")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("alerts", parents=[common], help="print alerts in the terminal")
    p.add_argument("--min-severity", choices=[s.value for s in Severity], default="low")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_alerts)

    p = sub.add_parser("dashboard", parents=[common], help="open the local web dashboard")
    p.add_argument("--port", type=int, default=8501)
    p.set_defaults(func=cmd_dashboard)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    for name in ("lang", "db", "config"):
        if not hasattr(args, name):
            setattr(args, name, None)
    lang = resolve_lang(args.lang)
    try:
        cfg = load_config(args.config)
        return args.func(args, cfg, lang)
    except LogWardenError as exc:
        print(f"{t('cli.error', lang)}: {exc.localized(lang)}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
