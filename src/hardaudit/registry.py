"""Registry of checks. New checks join the audit via the @check decorator."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from hardaudit.context import SystemContext
from hardaudit.models import CheckMeta, Outcome

CheckFunc = Callable[[SystemContext], Outcome]

REGISTRY: list[tuple[CheckMeta, CheckFunc]] = []


def check(**meta: Any) -> Callable[[CheckFunc], CheckFunc]:
    """Register a function as a check.

    Example:
        @check(id="SSH-001", title="...", group="ssh", severity=Severity.CRITICAL)
        def root_login(ctx): ...
    """

    def decorator(func: CheckFunc) -> CheckFunc:
        check_meta = CheckMeta(**meta)
        if any(existing.id == check_meta.id for existing, _ in REGISTRY):
            raise ValueError(f"Duplicate check id: {check_meta.id}")
        REGISTRY.append((check_meta, func))
        return func

    return decorator
