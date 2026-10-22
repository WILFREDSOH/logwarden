"""Risk scoring: an additive, explainable score capped at 100.

score = rule base score
      + privileged account bonus   (target is root/admin/...)
      + success bonus              (a successful login is part of the evidence)
      + volume bonus               (+5 per step reached: 2x, 4x, 8x the threshold)

Each contribution is kept as a ScoreItem so the alert can show *why* it got its score.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from logwarden.models import ScoreItem, Severity

# Upper bounds (exclusive) of each severity band.
SEVERITY_BANDS = ((30, Severity.LOW), (60, Severity.MEDIUM), (85, Severity.HIGH))


def severity_for(score: int) -> Severity:
    for upper, severity in SEVERITY_BANDS:
        if score < upper:
            return severity
    return Severity.CRITICAL


def volume_bonus(count: int, threshold: int, scoring: dict[str, Any]) -> int:
    if threshold <= 0:
        return 0
    reached = sum(1 for step in scoring["volume_steps"] if count >= step * threshold)
    return reached * scoring["volume_points"]


def compute_score(
    base: int,
    scoring: dict[str, Any],
    *,
    usernames: Iterable[str | None] = (),
    success: bool = False,
    count: int = 0,
    threshold: int = 0,
) -> tuple[int, Severity, tuple[ScoreItem, ...]]:
    items = [ScoreItem("score.base", base)]
    privileged = {name.lower() for name in scoring["privileged_accounts"]}
    if any(u and u.lower() in privileged for u in usernames):
        items.append(ScoreItem("score.privileged", scoring["privileged_bonus"]))
    if success:
        items.append(ScoreItem("score.success", scoring["success_bonus"]))
    if bonus := volume_bonus(count, threshold, scoring):
        items.append(ScoreItem("score.volume", bonus))
    raw_total = sum(i.points for i in items)
    total = max(0, min(100, raw_total))
    if total != raw_total:
        items.append(ScoreItem("score.cap", total - raw_total))
    return total, severity_for(total), tuple(items)
