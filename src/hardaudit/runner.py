"""Runs the registered checks and collects their results."""

from __future__ import annotations

from collections.abc import Iterable

import hardaudit.checks  # noqa: F401  (importing the package registers every check)
from hardaudit.context import SystemContext
from hardaudit.models import CheckResult, Outcome, SkipCheck, Status
from hardaudit.registry import REGISTRY


def available_groups() -> list[str]:
    """Check groups in registration order, without duplicates."""
    return list(dict.fromkeys(meta.group for meta, _ in REGISTRY))


def run_checks(ctx: SystemContext, groups: Iterable[str] | None = None) -> list[CheckResult]:
    """Run every check (or only the given groups). A failing check never stops the audit."""
    selected = set(groups) if groups else None
    results: list[CheckResult] = []

    for meta, func in REGISTRY:
        if selected is not None and meta.group not in selected:
            continue
        try:
            outcome = func(ctx)
        except SkipCheck as exc:
            outcome = Outcome(Status.SKIP, str(exc))
        except PermissionError as exc:
            # Files like /etc/shadow and /etc/sudoers are readable only by root.
            outcome = Outcome(Status.SKIP, f"Permission denied: {exc.filename}. Run with sudo.")
        except Exception as exc:
            outcome = Outcome(Status.ERROR, f"{type(exc).__name__}: {exc}")
        results.append(CheckResult(meta, outcome.status, outcome.detail, outcome.remediation))

    return results
