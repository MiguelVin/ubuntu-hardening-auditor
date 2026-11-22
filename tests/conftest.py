"""Shared fixtures: build a fake Ubuntu filesystem in a temp folder."""

from __future__ import annotations

import textwrap
from collections.abc import Callable

import pytest

from hardaudit.context import SystemContext
from hardaudit.models import CheckResult
from hardaudit.runner import run_checks

MakeRoot = Callable[[dict[str, str]], SystemContext]


@pytest.fixture
def make_root(tmp_path) -> MakeRoot:
    """make_root({"/etc/passwd": "..."}) -> SystemContext pointing at the fake root."""

    def _make(files: dict[str, str]) -> SystemContext:
        for absolute, content in files.items():
            path = tmp_path / absolute.lstrip("/")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(textwrap.dedent(content).lstrip("\n"))
        return SystemContext(tmp_path)

    return _make


def results_by_id(ctx: SystemContext, group: str) -> dict[str, CheckResult]:
    return {r.meta.id: r for r in run_checks(ctx, [group])}
