"""SSH server checks.

SSH is usually the only service exposed to the internet on a Linux server,
so it is the first door attackers knock on: password guessing (MITRE T1110)
and remote login (MITRE T1021.004).
"""

from __future__ import annotations

from collections.abc import Callable

from hardaudit.context import SystemContext
from hardaudit.models import Outcome, Severity, SkipCheck, failed, passed
from hardaudit.registry import check
from hardaudit.sshd import effective, parse_sshd_config

GROUP = "ssh"

# "00-" sorts before other drop-ins such as 50-cloud-init.conf, and in sshd the
# first value wins, so settings written here take precedence.
DROPIN = "/etc/ssh/sshd_config.d/00-hardening.conf"
RELOAD = "sudo sshd -t && sudo systemctl reload ssh"  # -t validates the config first


def _settings(ctx: SystemContext) -> dict[str, str]:
    settings = ctx.memo("sshd", lambda: parse_sshd_config(ctx))
    if settings is None:
        raise SkipCheck("OpenSSH server is not installed (no /etc/ssh/sshd_config)")
    return settings


def _expect(
    ctx: SystemContext,
    keyword: str,
    is_ok: Callable[[str], bool],
    fix_value: str,
    warning: str | None = None,
) -> Outcome:
    """Shared logic: read a keyword, judge it, and build the fix commands."""
    value, is_default = effective(_settings(ctx), keyword.lower())
    origin = "OpenSSH default" if is_default else "set in config"
    detail = f"{keyword} is '{value}' ({origin})"
    if is_ok(value):
        return passed(detail)
    fix = [f"# {warning}"] if warning else []
    fix += [f"echo '{keyword} {fix_value}' | sudo tee -a {DROPIN}", RELOAD]
    return failed(detail, fix)


@check(
    id="SSH-001",
    title="Root login over SSH is disabled",
    group=GROUP,
    severity=Severity.CRITICAL,
    mitre=("T1021.004", "T1110"),
)
def root_login(ctx: SystemContext) -> Outcome:
    # "prohibit-password" (the default) still lets root log in with a key.
    # Hardening guides recommend "no": log in as a normal user, then use sudo.
    return _expect(ctx, "PermitRootLogin", lambda v: v == "no", "no")


@check(
    id="SSH-002",
    title="SSH password authentication is disabled",
    group=GROUP,
    severity=Severity.HIGH,
    mitre=("T1110",),
)
def password_auth(ctx: SystemContext) -> Outcome:
    # With passwords off, only SSH keys work and brute force becomes useless.
    return _expect(
        ctx,
        "PasswordAuthentication",
        lambda v: v == "no",
        "no",
        warning="Make sure SSH key login works BEFORE this, or you will lock yourself out",
    )


@check(
    id="SSH-003",
    title="SSH login with empty passwords is disabled",
    group=GROUP,
    severity=Severity.CRITICAL,
    mitre=("T1078",),
)
def empty_passwords(ctx: SystemContext) -> Outcome:
    return _expect(ctx, "PermitEmptyPasswords", lambda v: v == "no", "no")


@check(
    id="SSH-004",
    title="SSH limits authentication attempts (MaxAuthTries <= 4)",
    group=GROUP,
    severity=Severity.MEDIUM,
    mitre=("T1110",),
)
def max_auth_tries(ctx: SystemContext) -> Outcome:
    # Fewer attempts per connection slows down password guessing.
    return _expect(ctx, "MaxAuthTries", lambda v: int(v) <= 4, "4")


@check(
    id="SSH-005",
    title="SSH X11 forwarding is disabled",
    group=GROUP,
    severity=Severity.LOW,
)
def x11_forwarding(ctx: SystemContext) -> Outcome:
    # Servers rarely need graphical apps over SSH; Ubuntu's default config enables it.
    return _expect(ctx, "X11Forwarding", lambda v: v == "no", "no")
