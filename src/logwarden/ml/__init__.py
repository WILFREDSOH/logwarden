"""Optional anomaly detection with an Isolation Forest (scikit-learn).

Why: the rules only catch what they were written for. A slow attack that stays
under every threshold produces no alert. The model looks at per-IP behaviour
over a time window and asks "does this look like the normal baseline?".

How:
  1. Events are aggregated per (source IP, time window) into numeric features,
     log-scaled (log1p) so that 40 failures is "far" but not infinitely far.
  2. The forest is fitted on baseline windows (normal activity) + the windows
     being scored. This is unsupervised: no label is used, so there is no label
     leakage. Including the scored windows matters because an Isolation Forest
     cannot extrapolate: values beyond the training range would all fall in the
     same leaf as the training maximum (we observed exactly that - see docs/ml.md).
  3. The alarm threshold is the (1 - q) quantile of the scores of the *baseline*
     windows only, i.e. about q of normal windows are flagged (q = 1% by default).
  4. Each anomaly lists the features that deviate most from the baseline median.

The model is never saved to disk: it is refitted on each run (well under a
second here), which avoids loading pickled files - a code-execution risk.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from logwarden.detection.rules.off_hours import OffHoursRule
from logwarden.errors import LogWardenError
from logwarden.models import Event, EventType

FEATURES = (
    "n_events",
    "n_failures",
    "n_success",
    "n_invalid_user",
    "failure_ratio",
    "n_users",
    "mean_gap_s",
    "off_hours_ratio",
)
MIN_TRAIN_WINDOWS = 20


def _window_start(ts: datetime, minutes: int) -> datetime:
    epoch = int(ts.timestamp())
    size = minutes * 60
    return datetime.fromtimestamp(epoch - epoch % size, UTC)


def build_windows(
    events: Iterable[Event], window_minutes: int, is_off_hours: Callable[[Event], bool]
) -> dict[tuple[str, datetime], dict[str, float]]:
    """Aggregate events into one feature vector per (source IP, window)."""
    buckets: dict[tuple[str, datetime], list[Event]] = defaultdict(list)
    for event in events:
        if event.src_ip:
            buckets[(event.src_ip, _window_start(event.timestamp, window_minutes))].append(event)

    features = {}
    for key, evs in sorted(buckets.items()):
        evs.sort(key=lambda e: e.timestamp)
        n = len(evs)
        failures = sum(1 for e in evs if e.event_type.is_failure)
        gaps = [
            (b.timestamp - a.timestamp).total_seconds() for a, b in zip(evs, evs[1:], strict=False)
        ]
        features[key] = {
            "n_events": n,
            "n_failures": failures,
            "n_success": sum(1 for e in evs if e.event_type is EventType.AUTH_SUCCESS),
            "n_invalid_user": sum(1 for e in evs if e.event_type is EventType.INVALID_USER),
            "failure_ratio": failures / n,
            "n_users": len({e.username for e in evs if e.username}),
            # one isolated event gets the full window as "gap": it is not a burst
            "mean_gap_s": sum(gaps) / len(gaps) if gaps else window_minutes * 60.0,
            "off_hours_ratio": sum(1 for e in evs if is_off_hours(e)) / n,
        }
    return features


def _require_sklearn() -> Any:
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
    except ImportError as exc:  # optional dependency
        raise LogWardenError("error.ml_missing") from exc
    return np, IsolationForest


def _median(values: Sequence[float]) -> float:
    ordered = sorted(values)
    mid = len(ordered) // 2
    return ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2


def score_anomalies(
    events: Sequence[Event], baseline: Sequence[Event] | None, cfg: dict[str, Any]
) -> list[dict[str, Any]]:
    """Return one row per (IP, window) of `events` with its anomaly score.

    If `baseline` is None the model is fitted on `events` itself (weaker: the
    threshold then flags the top q of the scored data by construction).
    """
    np, IsolationForest = _require_sklearn()
    mcfg = cfg["ml"]
    # Reuse the off-hours definition of rule LW-004 (same hours, timezone, weekends).
    off_hours = OffHoursRule(cfg["rules"]["LW-004"], cfg["scoring"]).is_off_hours
    target = build_windows(events, mcfg["window_minutes"], off_hours)
    train = build_windows(baseline, mcfg["window_minutes"], off_hours) if baseline else target
    if len(train) < MIN_TRAIN_WINDOWS:
        raise LogWardenError("error.ml_not_enough_data", n=len(train), needed=MIN_TRAIN_WINDOWS)
    if not target:
        return []

    def matrix(rows: Iterable[dict[str, float]]) -> Any:
        return np.log1p(np.array([[row[f] for f in FEATURES] for row in rows], dtype=float))

    x_train, x_target = matrix(train.values()), matrix(target.values())
    fit_data = np.vstack([x_train, x_target]) if baseline else x_train
    model = IsolationForest(
        n_estimators=mcfg["n_estimators"], random_state=mcfg["random_state"], contamination="auto"
    ).fit(fit_data)
    # score_samples: lower = more abnormal. We flip the sign so higher = more anomalous.
    train_scores = -model.score_samples(x_train)
    threshold = float(np.quantile(train_scores, 1 - mcfg["contamination_quantile"]))
    target_scores = -model.score_samples(x_target)

    medians = {f: _median([row[f] for row in train.values()]) for f in FEATURES}
    raw_train = [[row[f] for f in FEATURES] for row in train.values()]
    spreads = {
        f: float(
            np.percentile([r[i] for r in raw_train], 75)
            - np.percentile([r[i] for r in raw_train], 25)
        )
        for i, f in enumerate(FEATURES)
    }
    results = []
    for (ip, start), feats, score in zip(
        target.keys(), target.values(), target_scores, strict=True
    ):
        deviation = sorted(
            FEATURES,
            key=lambda f, feats=feats: (
                abs(feats[f] - medians[f]) / max(spreads[f], abs(medians[f]), 1.0)
            ),
            reverse=True,
        )
        results.append(
            {
                "src_ip": ip,
                "window_start": start.isoformat(),
                "score": round(float(score), 4),
                "threshold": round(threshold, 4),
                "is_anomaly": bool(score > threshold),
                "features": {f: round(float(v), 3) for f, v in feats.items()},
                "top_features": [
                    [f, round(float(feats[f]), 3), round(medians[f], 3)] for f in deviation[:3]
                ],
            }
        )
    results.sort(key=lambda r: r["score"], reverse=True)
    return results


def window_bounds(row: dict[str, Any], window_minutes: int) -> tuple[datetime, datetime]:
    start = datetime.fromisoformat(row["window_start"])
    return start, start + timedelta(minutes=window_minutes)
