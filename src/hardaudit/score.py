"""Risk score.

    score = 100 x (weight of passed checks / weight of evaluated checks)

Weights come from the severity (critical 10, high 6, medium 3, low 1), so one
critical failure costs more than several low ones. Skipped checks and errors
are left out: they were not evaluated, so they neither help nor hurt.
"""

from __future__ import annotations

from collections.abc import Iterable

from hardaudit.models import CheckResult, Status


def compute_score(results: Iterable[CheckResult]) -> int | None:
    """Score from 0 to 100, or None if nothing could be evaluated."""
    evaluated = [r for r in results if r.status in (Status.PASS, Status.FAIL)]
    total = sum(r.meta.severity.weight for r in evaluated)
    if total == 0:
        return None
    gained = sum(r.meta.severity.weight for r in evaluated if r.status is Status.PASS)
    return round(100 * gained / total)


def grade(score: int | None) -> tuple[str, str]:
    """Label and colour for a score."""
    if score is None:
        return "N/A", "white"
    if score >= 90:
        return "Good", "green"
    if score >= 70:
        return "Fair", "yellow"
    if score >= 50:
        return "Weak", "dark_orange"
    return "Critical", "red"
