"""Turn failed checks into a fix plan, then apply it."""

from __future__ import annotations

from dataclasses import dataclass, field

from hardaudit.context import SystemContext
from hardaudit.fix.actions import BackupStore, FixAction
from hardaudit.fix.fixers import FIXERS
from hardaudit.models import CheckResult, Status


@dataclass
class FixPlan:
    actions: list[FixAction] = field(default_factory=list)
    manual: list[CheckResult] = field(default_factory=list)  # failed, no safe auto-fix
    errors: dict[str, str] = field(default_factory=dict)  # check id -> why it could not plan


def plan_fixes(ctx: SystemContext, results: list[CheckResult], backups: BackupStore) -> FixPlan:
    plan = FixPlan()
    for result in results:
        if result.status is not Status.FAIL:
            continue
        fixer = FIXERS.get(result.meta.id)
        actions: list[FixAction] = []
        if fixer is not None:
            try:
                actions = fixer(ctx, backups)
            except Exception as exc:  # e.g. PermissionError when previewing without sudo
                plan.errors[result.meta.id] = f"{type(exc).__name__}: {exc}"
        if actions:
            plan.actions.extend(actions)
        else:
            plan.manual.append(result)
    return plan
