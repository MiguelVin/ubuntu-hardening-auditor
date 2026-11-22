"""Local account checks.

/etc/passwd fields: name:password:UID:GID:comment:home:shell
/etc/shadow fields: name:hash:last_change:... (readable only by root)

In /etc/shadow the hash field means:
  "$6$..."  a real password hash     "!" or "*"  account locked
  ""        NO password: anyone can log in as this user
"""

from __future__ import annotations

from pathlib import Path

from hardaudit.context import SystemContext
from hardaudit.models import Outcome, Severity, SkipCheck, failed, passed
from hardaudit.registry import check

GROUP = "accounts"


def _passwd_entries(ctx: SystemContext) -> list[list[str]]:
    text = ctx.read_text("/etc/passwd")
    if text is None:
        raise SkipCheck("/etc/passwd not found")
    entries = []
    for line in text.splitlines():
        fields = line.split(":")
        if line and not line.startswith("#") and len(fields) >= 7:
            entries.append(fields)
    return entries


@check(
    id="ACC-001",
    title="Only root has UID 0",
    group=GROUP,
    severity=Severity.CRITICAL,
    mitre=("T1078.003",),
)
def extra_uid_zero(ctx: SystemContext) -> Outcome:
    # Linux grants root powers by UID, not by name. A second account with
    # UID 0 is a classic backdoor left behind after an intrusion.
    extra = [f[0] for f in _passwd_entries(ctx) if f[2] == "0" and f[0] != "root"]
    if not extra:
        return passed("Only 'root' has UID 0")
    fix = ["# Check whether these accounts are legitimate before changing anything"]
    fix += [f"grep '^{name}:' /etc/passwd" for name in extra]
    fix += ["# If an account is not legitimate, lock and expire it"]
    fix += [f"sudo usermod -L -e 1 {name}" for name in extra]
    return failed(f"Accounts with UID 0 besides root: {', '.join(extra)}", fix)


@check(
    id="ACC-002",
    title="No account has an empty password",
    group=GROUP,
    severity=Severity.CRITICAL,
    mitre=("T1078.003",),
)
def empty_password(ctx: SystemContext) -> Outcome:
    text = ctx.read_text("/etc/shadow")  # PermissionError -> SKIP (needs sudo)
    if text is None:
        raise SkipCheck("/etc/shadow not found")
    empty = []
    for line in text.splitlines():
        fields = line.split(":")
        if len(fields) >= 2 and fields[0] and fields[1] == "":
            empty.append(fields[0])
    if not empty:
        return passed("Every account has a password hash or is locked")
    fix = [
        f"sudo passwd -l {name}  # lock; set a password later with: sudo passwd {name}"
        for name in empty
    ]
    return failed(f"Accounts without a password: {', '.join(empty)}", fix)


def _sudoers_files(ctx: SystemContext) -> list[Path]:
    files = []
    main = ctx.path("/etc/sudoers")
    if main.is_file():
        files.append(main)
    drop_dir = ctx.path("/etc/sudoers.d")
    if drop_dir.is_dir():
        for path in sorted(drop_dir.iterdir()):
            # sudo ignores files whose name ends in "~" or contains "." (man sudoers)
            if path.is_file() and not path.name.endswith("~") and "." not in path.name:
                files.append(path)
    return files


@check(
    id="ACC-003",
    title="sudo always asks for a password (no NOPASSWD)",
    group=GROUP,
    severity=Severity.HIGH,
    mitre=("T1548.003",),
)
def sudo_nopasswd(ctx: SystemContext) -> Outcome:
    # NOPASSWD means anyone who takes over that user's session (a stolen
    # SSH key, a malicious script) becomes root instantly.
    files = _sudoers_files(ctx)
    if not files:
        raise SkipCheck("sudo is not installed (no /etc/sudoers)")
    hits: list[tuple[str, int]] = []
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")  # root only
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if "NOPASSWD" in stripped and not stripped.startswith("#"):
                hits.append((ctx.display(path), number))
    if not hits:
        return passed(f"No NOPASSWD rule in {len(files)} sudoers file(s)")
    detail = "NOPASSWD found at " + ", ".join(f"{file}:{line}" for file, line in hits)
    fix = [f"sudo visudo -f {file}  # remove NOPASSWD on line {line}" for file, line in hits]
    return failed(detail, fix)
