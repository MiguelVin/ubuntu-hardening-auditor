"""Building blocks for automatic fixes: actions and backups."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass
class FixAction:
    """One change that --fix can apply. Nothing happens until apply() is called."""

    check_id: str
    description: str
    apply: Callable[[], None]


@dataclass
class AppliedFix:
    action: FixAction
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


class BackupStore:
    """Keeps a copy of each file before its first change.

    The copy is named <file>.hardaudit-<timestamp>.bak and is ALWAYS created
    with mode 600: a backup of a world-readable /etc/shadow must not leak the
    password hashes again. Creating it with os.open(..., 0o600) avoids the
    short moment in which a copy-then-chmod would be readable by everyone.
    """

    def __init__(self, stamp: str | None = None) -> None:
        self.stamp = stamp or datetime.now().strftime("%Y%m%d-%H%M%S")
        # file -> its backup, or None if the file did not exist before this run
        self._seen: dict[Path, Path | None] = {}

    @property
    def saved(self) -> dict[Path, Path]:
        """Files that were backed up (files created by this run need no backup)."""
        return {path: backup for path, backup in self._seen.items() if backup is not None}

    def save(self, path: Path) -> None:
        if path in self._seen:
            return  # only the state BEFORE the first change matters
        if not path.exists():
            self._seen[path] = None
            return
        backup = path.with_name(f"{path.name}.hardaudit-{self.stamp}.bak")
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(path.read_bytes())
        self._seen[path] = backup


def run_all(actions: list[FixAction]) -> list[AppliedFix]:
    """Apply every action; one failure never stops the others."""
    applied = []
    for action in actions:
        try:
            action.apply()
            applied.append(AppliedFix(action))
        except Exception as exc:
            applied.append(AppliedFix(action, f"{type(exc).__name__}: {exc}"))
    return applied
