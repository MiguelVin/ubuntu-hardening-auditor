"""Automatic fixes, one function per check that is safe to fix.

Each fixer looks at the system and returns the actions it would take; the
actions only change files when apply() is called. Every path goes through
ctx, so fixes also work (and are tested) on a --root folder.

Checks WITHOUT a fixer on purpose:
  ACC-001 extra UID 0     -> deleting/locking an account needs a human decision
  ACC-003 sudo NOPASSWD   -> a broken sudoers file can lock everyone out of sudo
  NET-001 firewall        -> enabling UFW without an SSH rule cuts remote access
  NET-002 exposed service -> stopping it may break an application
  NET-003/004 sysctl      -> routing changes can break Docker and VPNs
  LOG-001 brute force     -> evidence of an attack: investigate, don't auto-ban
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from stat import S_IMODE, S_ISGID, S_ISUID, S_IWOTH

from hardaudit.checks.passwords import (
    PAM_PASSWORD,
    PWQUALITY_DROPIN,
    REQUIRED_MINLEN,
    pwquality_line,
)
from hardaudit.checks.permissions import (
    ACCOUNT_FILES,
    is_gtfobin,
    scan_suid,
    world_writable_paths,
)
from hardaudit.checks.ssh import DROPIN as SSH_DROPIN
from hardaudit.context import SystemContext
from hardaudit.fix.actions import BackupStore, FixAction
from hardaudit.sshd import SSHD_CONFIG

Fixer = Callable[[SystemContext, BackupStore], list[FixAction]]
FIXERS: dict[str, Fixer] = {}


def fixer(check_id: str) -> Callable[[Fixer], Fixer]:
    def decorator(func: Fixer) -> Fixer:
        FIXERS[check_id] = func
        return func

    return decorator


# --- SSH -------------------------------------------------------------------

SSH_SETTINGS = {
    "SSH-001": ("PermitRootLogin", "no"),
    "SSH-002": ("PasswordAuthentication", "no"),
    "SSH-003": ("PermitEmptyPasswords", "no"),
    "SSH-004": ("MaxAuthTries", "4"),
    "SSH-005": ("X11Forwarding", "no"),
}
INCLUDE_LINE = "Include /etc/ssh/sshd_config.d/*.conf"


def _includes_dropins(main_text: str) -> bool:
    for line in main_text.splitlines():
        words = line.split()
        if words and words[0].lower() == "include" and "sshd_config.d" in line:
            return True
    return False


def _validate_sshd(ctx: SystemContext) -> None:
    """Run `sshd -t` on the real system; raise if the new config is invalid."""
    if ctx.root != Path("/") or shutil.which("sshd") is None:
        return  # auditing a mounted folder: the local sshd cannot validate it
    check = subprocess.run(["sshd", "-t"], capture_output=True, text=True, check=False)
    if check.returncode != 0:
        raise RuntimeError(f"sshd -t rejected the change: {check.stderr.strip()}")


def set_sshd_option(ctx: SystemContext, backups: BackupStore, keyword: str, value: str) -> None:
    """Write `keyword value` to the hardening drop-in, validating with sshd -t.

    If validation fails, both files go back to their previous content.
    """
    dropin, main = ctx.path(SSH_DROPIN), ctx.path(SSHD_CONFIG)
    old_dropin = dropin.read_text() if dropin.exists() else None
    old_main = main.read_text()

    backups.save(dropin)
    lines = old_dropin.splitlines() if old_dropin else ["# Managed by hardaudit --fix"]
    # Drop any previous value of this keyword (keywords are case-insensitive).
    lines = [
        line
        for line in lines
        if line.split()[:1] != [keyword] and not line.lower().startswith(keyword.lower() + " ")
    ]
    lines.append(f"{keyword} {value}")
    dropin.parent.mkdir(parents=True, exist_ok=True)
    dropin.write_text("\n".join(lines) + "\n")

    if not _includes_dropins(old_main):
        # Without this line sshd never reads the drop-in. At the top, so it wins.
        backups.save(main)
        main.write_text(f"{INCLUDE_LINE}\n{old_main}")

    try:
        _validate_sshd(ctx)
    except RuntimeError:
        main.write_text(old_main)
        if old_dropin is None:
            dropin.unlink()
        else:
            dropin.write_text(old_dropin)
        raise


def _ssh_fixer(check_id: str) -> Fixer:
    keyword, value = SSH_SETTINGS[check_id]

    def plan(ctx: SystemContext, backups: BackupStore) -> list[FixAction]:
        return [
            FixAction(
                check_id,
                f"Set '{keyword} {value}' in {SSH_DROPIN} (restart sshd to apply)",
                lambda: set_sshd_option(ctx, backups, keyword, value),
            )
        ]

    return plan


for _check_id in SSH_SETTINGS:
    fixer(_check_id)(_ssh_fixer(_check_id))


# --- Accounts --------------------------------------------------------------


@fixer("ACC-002")
def lock_passwordless_accounts(ctx: SystemContext, backups: BackupStore) -> list[FixAction]:
    shadow = ctx.path("/etc/shadow")
    names = [
        fields[0]
        for fields in (line.split(":") for line in shadow.read_text().splitlines())
        if len(fields) >= 2 and fields[0] and fields[1] == ""
    ]

    def apply() -> None:
        backups.save(shadow)
        lines = []
        for line in shadow.read_text().splitlines():
            fields = line.split(":")
            if len(fields) >= 2 and fields[0] and fields[1] == "":
                fields[1] = "!"  # "!" = locked, exactly what `passwd -l` does
            lines.append(":".join(fields))
        # write_text reuses the same file, so its owner and mode do not change
        shadow.write_text("\n".join(lines) + "\n")

    return [FixAction("ACC-002", f"Lock accounts without a password: {', '.join(names)}", apply)]


# --- Permissions -----------------------------------------------------------


@fixer("PERM-001")
def fix_account_file_permissions(ctx: SystemContext, backups: BackupStore) -> list[FixAction]:
    actions = []
    for absolute, allowed in ACCOUNT_FILES.items():
        info = ctx.stat(absolute)
        if info is None:
            continue
        path = ctx.path(absolute)
        mode = S_IMODE(info.st_mode)
        new_mode = mode & allowed  # remove only the extra bits; stricter modes stay
        if new_mode != mode:
            actions.append(
                FixAction(
                    "PERM-001",
                    f"chmod {absolute}: {mode:o} -> {new_mode:o}",
                    lambda p=path, m=new_mode: os.chmod(p, m),
                )
            )
        if info.st_uid != 0:
            actions.append(
                FixAction(
                    "PERM-001",
                    f"chown {absolute}: uid {info.st_uid} -> root",
                    lambda p=path: os.chown(p, 0, -1),
                )
            )
    return actions


@fixer("PERM-002")
def fix_world_writable(ctx: SystemContext, backups: BackupStore) -> list[FixAction]:
    paths = world_writable_paths(ctx)

    def apply() -> None:
        for path in paths:
            os.chmod(path, S_IMODE(path.lstat().st_mode) & ~S_IWOTH)

    shown = ", ".join(ctx.display(p) for p in paths[:5]) + (" ..." if len(paths) > 5 else "")
    return [FixAction("PERM-002", f"Remove write permission for others: {shown}", apply)]


@fixer("PERM-003")
def fix_gtfobins_suid(ctx: SystemContext, backups: BackupStore) -> list[FixAction]:
    # Only programs that are known to give a root shell. Unknown SUID
    # programs may really need it, so they are left for a human to decide.
    _, unexpected = scan_suid(ctx)
    actions = []
    for path in (p for p in unexpected if is_gtfobin(p)):
        mode = S_IMODE(path.lstat().st_mode)
        actions.append(
            FixAction(
                "PERM-003",
                f"Remove SUID/SGID from {ctx.display(path)} (GTFOBins: root shell)",
                lambda p=path, m=mode: os.chmod(p, m & ~(S_ISUID | S_ISGID)),
            )
        )
    return actions


# --- Passwords -------------------------------------------------------------


@fixer("PWD-001")
def set_password_min_length(ctx: SystemContext, backups: BackupStore) -> list[FixAction]:
    line = pwquality_line(ctx.read_text(PAM_PASSWORD) or "")
    if line is None:
        return []  # needs `apt install libpam-pwquality`: left as a manual step
    if "minlen=" in line:
        return []  # minlen on the PAM line overrides the conf files: edit PAM by hand
    dropin = ctx.path(PWQUALITY_DROPIN)

    def apply() -> None:
        backups.save(dropin)
        dropin.parent.mkdir(parents=True, exist_ok=True)
        dropin.write_text(f"# Managed by hardaudit --fix\nminlen = {REQUIRED_MINLEN}\n")

    return [FixAction("PWD-001", f"Set minlen = {REQUIRED_MINLEN} in {PWQUALITY_DROPIN}", apply)]
