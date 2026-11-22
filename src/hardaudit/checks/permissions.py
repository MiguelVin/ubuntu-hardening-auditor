"""File permission checks.

Linux permissions in octal: each digit is owner / group / others, and each
digit is the sum of read (4) + write (2) + execute (1).

    640 = owner rw- (6), group r-- (4), others --- (0)

Special bits come before those three digits:
    SUID (4000): the program runs with the privileges of the file OWNER.
                 SUID + owner root = runs as root, even if a normal user starts it.
    SGID (2000): same idea, for the file's group.
    sticky (1000): on a directory, users can only delete their own files (/tmp).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from stat import S_IMODE, S_ISDIR, S_ISGID, S_ISLNK, S_ISREG, S_ISUID, S_ISVTX, S_IWOTH

from hardaudit.context import SystemContext
from hardaudit.models import Outcome, Severity, SkipCheck, failed, passed
from hardaudit.registry import check

GROUP = "permissions"
MAX_LISTED = 10

# Most permissive mode allowed for each file (CIS Ubuntu Benchmark).
ACCOUNT_FILES = {
    "/etc/passwd": 0o644,
    "/etc/group": 0o644,
    "/etc/shadow": 0o640,  # password hashes: never readable by everyone
    "/etc/gshadow": 0o640,
}


def _summarize(items: list[str]) -> str:
    extra = len(items) - MAX_LISTED
    listed = ", ".join(items[:MAX_LISTED])
    return f"{listed} (+{extra} more)" if extra > 0 else listed


@check(
    id="PERM-001",
    title="Account database files have safe permissions",
    group=GROUP,
    severity=Severity.HIGH,
    mitre=("T1003.008",),
)
def account_files(ctx: SystemContext) -> Outcome:
    problems: list[str] = []
    fix: list[str] = []
    found = 0
    for path, allowed in ACCOUNT_FILES.items():
        info = ctx.stat(path)
        if info is None:
            continue
        found += 1
        mode = S_IMODE(info.st_mode)
        issues = []
        if mode & ~allowed:  # any bit set that is not allowed
            issues.append(f"mode {mode:o} (max {allowed:o})")
        if info.st_uid != 0:
            issues.append(f"owner uid {info.st_uid} (expected root)")
        if issues:
            problems.append(f"{path}: {', '.join(issues)}")
            fix.append(f"sudo chown root {path} && sudo chmod {allowed:o} {path}")
    if not found:
        raise SkipCheck("No account database file found in /etc")
    if not problems:
        return passed(f"{found} files checked: mode and owner are correct")
    return failed("; ".join(problems), fix)


def world_writable_paths(ctx: SystemContext) -> list[Path]:
    """Files and directories in /etc that anyone can write to (also used by --fix)."""
    base = ctx.path("/etc")
    if not base.is_dir():
        raise SkipCheck("/etc not found")
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(base):
        for name in sorted(dirnames + filenames):
            path = Path(dirpath) / name
            try:
                info = path.lstat()
            except OSError:
                continue
            if S_ISLNK(info.st_mode):
                continue  # symlinks always show 777; what matters is their target
            sticky_dir = S_ISDIR(info.st_mode) and info.st_mode & S_ISVTX
            if info.st_mode & S_IWOTH and not sticky_dir:
                found.append(path)
    return found


@check(
    id="PERM-002",
    title="No world-writable files in /etc",
    group=GROUP,
    severity=Severity.HIGH,
    mitre=("T1222.002",),
)
def world_writable_etc(ctx: SystemContext) -> Outcome:
    # /etc holds system configuration. If anyone can write to a file there,
    # any user can change how the system behaves (and often become root).
    found = [ctx.display(path) for path in world_writable_paths(ctx)]
    if not found:
        return passed("No world-writable file or directory in /etc")
    fix = [f"sudo chmod o-w {path}" for path in found[:MAX_LISTED]]
    return failed(f"World-writable: {_summarize(found)}", fix)


BIN_DIRS = ("/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/bin", "/sbin")

# SUID/SGID programs that Ubuntu ships on purpose (they need privileges to work,
# e.g. passwd must write /etc/shadow).
EXPECTED_SUID = frozenset(
    {
        "at", "bsd-write", "chage", "chfn", "chsh", "crontab", "dotlockfile", "expiry",
        "fusermount", "fusermount3", "gpasswd", "mount", "mount.cifs", "mount.ecryptfs_private",
        "mount.nfs", "mtr-packet", "newgidmap", "newgrp", "newuidmap", "ntfs-3g",
        "pam_extrausers_chkpwd", "passwd", "pkexec", "plocate", "pppd", "ssh-agent", "su",
        "sudo", "umount", "umount.nfs", "unix_chkpwd", "wall", "write",
        # Ubuntu 25.10+ ships sudo-rs as "sudo" and keeps the classic one as "sudo.ws"
        "sudo.ws", "sudoedit.ws", "sudo-rs", "su-rs",
    }
)  # fmt: skip

# Programs that give a root shell when they have SUID (see gtfobins.github.io).
GTFOBINS = frozenset(
    {
        "awk", "base64", "bash", "chmod", "chown", "cp", "curl", "dash", "dd", "docker", "ed",
        "env", "find", "gawk", "git", "less", "more", "mv", "nano", "nmap", "node", "openssl",
        "perl", "php", "python", "rsync", "ruby", "sed", "sh", "systemctl", "tar", "tee", "vi",
        "vim", "wget", "xxd", "zip", "zsh",
    }
)  # fmt: skip


def _base_name(name: str) -> str:
    """python3.14 -> python, so versioned names match GTFOBINS."""
    return re.sub(r"[\d.]+$", "", name)


def is_gtfobin(path: Path) -> bool:
    return _base_name(path.name) in GTFOBINS


def scan_suid(ctx: SystemContext) -> tuple[int, list[Path]]:
    """(total SUID/SGID binaries, the unexpected ones). Also used by --fix."""
    seen_dirs: set[Path] = set()
    total = 0
    unexpected: list[Path] = []
    for directory in BIN_DIRS:
        path = ctx.path(directory)
        if not path.is_dir():
            continue
        real = path.resolve()  # on Ubuntu /bin -> /usr/bin: scan it only once
        if real in seen_dirs:
            continue
        seen_dirs.add(real)
        for entry in sorted(path.iterdir()):
            try:
                info = entry.lstat()
            except OSError:
                continue
            if not S_ISREG(info.st_mode) or not info.st_mode & (S_ISUID | S_ISGID):
                continue
            total += 1
            if entry.name not in EXPECTED_SUID:
                unexpected.append(entry)
    if not seen_dirs:
        raise SkipCheck("No binary directory found")
    return total, unexpected


@check(
    id="PERM-003",
    title="No unexpected SUID/SGID binaries",
    group=GROUP,
    severity=Severity.HIGH,
    mitre=("T1548.001",),
)
def suid_binaries(ctx: SystemContext) -> Outcome:
    total, unexpected = scan_suid(ctx)
    if not unexpected:
        return passed(f"{total} SUID/SGID binaries found, all expected on Ubuntu")
    labels = [
        ctx.display(path) + (" [GTFOBins: root shell]" if is_gtfobin(path) else "")
        for path in unexpected
    ]
    fix = ["# Confirm each program really does not need SUID/SGID before removing it"]
    fix += [f"sudo chmod u-s,g-s {ctx.display(path)}" for path in unexpected[:MAX_LISTED]]
    return failed(f"Unexpected SUID/SGID: {_summarize(labels)}", fix)
