"""One report structure shared by the JSON, Markdown and HTML outputs."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from hardaudit import __version__
from hardaudit.models import CheckResult, Status
from hardaudit.score import compute_score, grade


def mitre_url(technique: str) -> str:
    """T1110.001 -> https://attack.mitre.org/techniques/T1110/001/"""
    return "https://attack.mitre.org/techniques/" + technique.replace(".", "/") + "/"


def build_report(
    results: list[CheckResult], target: str, generated_at: datetime | None = None
) -> dict:
    score = compute_score(results)
    label, _ = grade(score)
    counts = Counter(r.status for r in results)
    generated = (generated_at or datetime.now(UTC)).replace(microsecond=0)
    return {
        "tool": "hardaudit",
        "version": __version__,
        "target": target,
        "generated_at": generated.isoformat(),
        "score": score,
        "grade": label,
        "evaluated": counts[Status.PASS] + counts[Status.FAIL],
        "total": len(results),
        "counts": {status.value: counts[status] for status in Status},
        "results": [r.to_dict() for r in results],
    }
