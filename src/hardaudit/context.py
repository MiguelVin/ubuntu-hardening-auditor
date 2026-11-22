"""Access to the filesystem being audited."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

T = TypeVar("T")


class SystemContext:
    """Gives checks access to the audited filesystem.

    Every path is resolved against ``root``. In a real audit ``root`` is "/";
    in tests it is a temporary folder holding fake config files. This is what
    lets every check be tested without touching the real system.
    """

    def __init__(self, root: Path | str = "/") -> None:
        self.root = Path(root)
        self._cache: dict[str, Any] = {}

    def path(self, absolute: str) -> Path:
        """Map an absolute system path (e.g. /etc/passwd) into the audited root."""
        return self.root / absolute.lstrip("/")

    def display(self, path: Path) -> str:
        """Turn a path inside the root back into the system path shown to users."""
        return "/" + path.relative_to(self.root).as_posix()

    def read_text(self, absolute: str) -> str | None:
        """Return the file content, or None if the file does not exist.

        PermissionError is deliberately NOT caught: the runner turns it into a
        SKIP that tells the user to run with sudo.
        """
        try:
            return self.path(absolute).read_text(encoding="utf-8", errors="replace")
        except (FileNotFoundError, NotADirectoryError):
            return None

    def glob(self, absolute_pattern: str) -> list[Path]:
        """Files matching a glob such as /etc/ssh/sshd_config.d/*.conf, sorted."""
        return sorted(p for p in self.root.glob(absolute_pattern.lstrip("/")) if p.is_file())

    def memo(self, key: str, factory: Callable[[], T]) -> T:
        """Compute a value once per audit (e.g. the parsed sshd config)."""
        if key not in self._cache:
            self._cache[key] = factory()
        return self._cache[key]
