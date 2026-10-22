"""PNG charts for the report (matplotlib, headless backend)."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # no display needed (WSL, CI, servers)
import matplotlib.dates as mdates  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import MaxNLocator  # noqa: E402

from logwarden.i18n import t  # noqa: E402
from logwarden.models import Severity  # noqa: E402
from logwarden.reporting.stats import Summary  # noqa: E402

SEVERITY_COLORS = {
    Severity.LOW.value: "#4C8BF5",
    Severity.MEDIUM.value: "#E8A33D",
    Severity.HIGH.value: "#E0603A",
    Severity.CRITICAL.value: "#B4232C",
}
FAILURE_COLOR = "#D1495B"
SUCCESS_COLOR = "#3E8E7E"
NEUTRAL_COLOR = "#5C6B7A"


def _style(ax: plt.Axes, title: str) -> None:
    ax.set_title(title, loc="left", fontsize=12, fontweight="bold", pad=12)
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax.margins(y=0.12)
    ax.spines[["top", "right"]].set_visible(False)
    ax.grid(axis="y", alpha=0.25)


def _save(fig: plt.Figure, path: Path) -> Path:
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)
    return path


def severity_figure(s: Summary, lang: str) -> plt.Figure:
    fig, ax = plt.subplots(figsize=(6, 3.2))
    labels = [t(f"severity.{k}", lang) for k in s.by_severity]
    bars = ax.bar(
        labels, list(s.by_severity.values()), color=[SEVERITY_COLORS[k] for k in s.by_severity]
    )
    ax.bar_label(bars)
    _style(ax, t("chart.alerts_by_severity", lang))
    return fig


def rule_figure(s: Summary, lang: str) -> plt.Figure:
    fig, ax = plt.subplots(figsize=(6, 3.2))
    labels = [f"{rid}\n{t(f'rule.{rid}.short', lang)}" for rid in s.by_rule]
    bars = ax.bar(labels, list(s.by_rule.values()), color=NEUTRAL_COLOR)
    ax.bar_label(bars)
    ax.tick_params(axis="x", labelsize=8)
    _style(ax, t("chart.alerts_by_rule", lang))
    return fig


def timeline_figure(s: Summary, lang: str) -> plt.Figure:
    fig, ax = plt.subplots(figsize=(10, 3.4))
    hours = list(s.hourly)
    fails = [v["failures"] for v in s.hourly.values()]
    oks = [v["successes"] for v in s.hourly.values()]
    width = 1 / 24 * 0.9
    ax.bar(hours, oks, width=width, color=SUCCESS_COLOR, label=t("chart.successes", lang))
    ax.bar(
        hours, fails, width=width, bottom=oks, color=FAILURE_COLOR, label=t("chart.failures", lang)
    )
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%m-%d %Hh"))
    ax.set_ylabel(t("chart.events_per_hour", lang))
    ax.legend(frameon=False)
    _style(ax, t("chart.timeline", lang))
    return fig


def top_ips_figure(s: Summary, lang: str) -> plt.Figure:
    fig, ax = plt.subplots(figsize=(6, 3.6))
    items = list(reversed(s.top_failure_ips))
    bars = ax.barh([ip for ip, _ in items], [n for _, n in items], color=FAILURE_COLOR)
    ax.bar_label(bars, padding=2)
    ax.grid(axis="x", alpha=0.25)
    ax.set_title(t("chart.top_ips", lang), loc="left", fontsize=12, fontweight="bold")
    ax.spines[["top", "right"]].set_visible(False)
    return fig


def render_all(s: Summary, lang: str, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    charts = [_save(severity_figure(s, lang), out_dir / "alerts_by_severity.png")]
    if s.hourly:
        charts.append(_save(timeline_figure(s, lang), out_dir / "timeline.png"))
    if s.by_rule:
        charts.append(_save(rule_figure(s, lang), out_dir / "alerts_by_rule.png"))
    if s.top_failure_ips:
        charts.append(_save(top_ips_figure(s, lang), out_dir / "top_failure_ips.png"))
    return charts
