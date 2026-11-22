"""Minimal parser for the OpenSSH server configuration (sshd_config).

Rules from `man sshd_config` that matter here:

- Keywords are case-insensitive, and "Key value" or "Key=value" are both valid.
- For most keywords the FIRST value found wins. That is why Ubuntu puts
  `Include /etc/ssh/sshd_config.d/*.conf` at the top of the file: drop-in
  files override whatever comes later in the main file.
- `Match` starts a conditional block (per user, IP...). We only evaluate the
  global settings, so parsing a file stops at its first `Match`.
"""

from __future__ import annotations

import re

from hardaudit.context import SystemContext

SSHD_CONFIG = "/etc/ssh/sshd_config"
SSH_DIR = "/etc/ssh"
MAX_INCLUDE_DEPTH = 5

_LINE = re.compile(r"^(\S+?)(?:\s*=\s*|\s+)(.+)$")

# OpenSSH defaults, used when a keyword is not set anywhere.
DEFAULTS = {
    "permitrootlogin": "prohibit-password",
    "passwordauthentication": "yes",
    "permitemptypasswords": "no",
    "maxauthtries": "6",
    "x11forwarding": "no",
}


def parse_sshd_config(ctx: SystemContext) -> dict[str, str] | None:
    """Effective global settings (lower-case keys), or None if sshd is not installed."""
    text = ctx.read_text(SSHD_CONFIG)
    if text is None:
        return None
    settings: dict[str, str] = {}
    _parse_text(ctx, text, settings, depth=0)
    return settings


def _parse_text(ctx: SystemContext, text: str, settings: dict[str, str], depth: int) -> None:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _LINE.match(line)
        if not match:
            continue
        key = match.group(1).lower()
        value = match.group(2).strip().strip('"')

        if key == "match":
            return
        if key == "include":
            if depth < MAX_INCLUDE_DEPTH:
                _parse_include(ctx, value, settings, depth)
            continue
        settings.setdefault(key, value)  # first value wins


def _parse_include(ctx: SystemContext, value: str, settings: dict[str, str], depth: int) -> None:
    for pattern in value.split():
        # Relative Include paths are relative to /etc/ssh.
        absolute = pattern if pattern.startswith("/") else f"{SSH_DIR}/{pattern}"
        for path in ctx.glob(absolute):
            text = path.read_text(encoding="utf-8", errors="replace")
            _parse_text(ctx, text, settings, depth + 1)


def effective(settings: dict[str, str], key: str) -> tuple[str, bool]:
    """Return (value, is_default) for a keyword, value in lower case."""
    if key in settings:
        return settings[key].lower(), False
    return DEFAULTS[key], True
