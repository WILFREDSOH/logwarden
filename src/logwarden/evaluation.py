"""Compare rule alerts and ML anomalies with the ground truth of a synthetic dataset.

Two views:
  * per scenario: did the expected rules fire? did the model flag the attacker?
  * per (source IP, time window): confusion matrix for rules, ML and both combined.

This only measures how well LogWarden finds the attacks *we* injected into data
*we* generated. It is a regression test of the detection logic, not evidence of
real-world performance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from logwarden.models import Alert
from logwarden.synth import GroundTruth, Scenario


@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def add(self, predicted: bool, actual: bool) -> None:
        if predicted and actual:
            self.tp += 1
        elif predicted:
            self.fp += 1
        elif actual:
            self.fn += 1
        else:
            self.tn += 1

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None


@dataclass
class ScenarioResult:
    scenario: Scenario
    rules_fired: list[str]
    expected_ok: bool
    ml_flagged: bool | None  # None when no ML scores are available


@dataclass
class Evaluation:
    scenarios: list[ScenarioResult] = field(default_factory=list)
    alerts_outside_scenarios: int = 0
    windows: dict[str, Confusion] = field(default_factory=dict)


def _overlaps(a0: datetime, a1: datetime, b0: datetime, b1: datetime) -> bool:
    return a0 <= b1 and b0 <= a1


def _span(sc: Scenario) -> tuple[datetime, datetime]:
    return datetime.fromisoformat(sc.start), datetime.fromisoformat(sc.end)


def evaluate(
    gt: GroundTruth, alerts: list[Alert], anomalies: list[dict[str, Any]], window_minutes: int
) -> Evaluation:
    result = Evaluation()
    win = timedelta(minutes=window_minutes)
    malicious = [s for s in gt.scenarios if s.malicious]

    for sc in gt.scenarios:
        t0, t1 = _span(sc)
        fired = sorted(
            {
                a.rule_id
                for a in alerts
                if a.src_ip == sc.src_ip and _overlaps(a.first_seen, a.last_seen, t0, t1)
            }
        )
        ml = None
        if anomalies:
            ml = any(
                r["is_anomaly"]
                and r["src_ip"] == sc.src_ip
                and _overlaps(
                    datetime.fromisoformat(r["window_start"]),
                    datetime.fromisoformat(r["window_start"]) + win,
                    t0,
                    t1,
                )
                for r in anomalies
            )
        result.scenarios.append(ScenarioResult(sc, fired, set(sc.expected_rules) <= set(fired), ml))

    result.alerts_outside_scenarios = sum(
        1
        for a in alerts
        if not any(
            a.src_ip == s.src_ip and _overlaps(a.first_seen, a.last_seen, *_span(s))
            for s in malicious
        )
    )

    if anomalies:
        rules_c, ml_c, both_c = Confusion(), Confusion(), Confusion()
        for row in anomalies:
            w0 = datetime.fromisoformat(row["window_start"])
            w1 = w0 + win
            actual = any(
                s.src_ip == row["src_ip"] and _overlaps(w0, w1, *_span(s)) for s in malicious
            )
            by_rules = any(
                a.src_ip == row["src_ip"] and _overlaps(a.first_seen, a.last_seen, w0, w1)
                for a in alerts
            )
            rules_c.add(by_rules, actual)
            ml_c.add(row["is_anomaly"], actual)
            both_c.add(by_rules or row["is_anomaly"], actual)
        result.windows = {"rules": rules_c, "ml": ml_c, "rules_or_ml": both_c}
    return result
