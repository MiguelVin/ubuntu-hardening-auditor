"""Password policy: minimum length enforced by PAM.

PAM (Pluggable Authentication Modules) decides how Linux checks passwords.
The module pam_pwquality rejects weak passwords when a user runs `passwd`.

Why length and not forced expiry? NIST SP 800-63B recommends long passwords
and no periodic forced changes: length is what makes brute force expensive.

Where minlen comes from (later wins):
  1. pam_pwquality built-in default: 8
  2. /etc/security/pwquality.conf, then /etc/security/pwquality.conf.d/*.conf
  3. minlen=N on the pam_pwquality line in /etc/pam.d/common-password
"""

from __future__ import annotations

import re

from hardaudit.context import SystemContext
from hardaudit.models import Outcome, Severity, SkipCheck, failed, passed
from hardaudit.registry import check

GROUP = "passwords"
PAM_PASSWORD = "/etc/pam.d/common-password"
REQUIRED_MINLEN = 14
DEFAULT_MINLEN = 8

_CONF_MINLEN = re.compile(r"^\s*minlen\s*=\s*(\d+)", re.MULTILINE)
_ARG_MINLEN = re.compile(r"\bminlen=(\d+)")

PWQUALITY_DROPIN = "/etc/security/pwquality.conf.d/60-hardening.conf"
FIX = [
    "sudo apt install libpam-pwquality",
    f"echo 'minlen = {REQUIRED_MINLEN}' | sudo tee {PWQUALITY_DROPIN}",
]


def pwquality_line(pam_text: str) -> str | None:
    for line in pam_text.splitlines():
        if "pam_pwquality.so" in line and not line.strip().startswith("#"):
            return line
    return None


def effective_minlen(ctx: SystemContext, pam_line: str) -> int:
    minlen = DEFAULT_MINLEN
    conf_files = ["/etc/security/pwquality.conf"]
    conf_files += [ctx.display(p) for p in ctx.glob("/etc/security/pwquality.conf.d/*.conf")]
    for path in conf_files:
        for match in _CONF_MINLEN.finditer(ctx.read_text(path) or ""):
            minlen = int(match.group(1))
    arg = _ARG_MINLEN.search(pam_line)
    return int(arg.group(1)) if arg else minlen


@check(
    id="PWD-001",
    title=f"Passwords must have at least {REQUIRED_MINLEN} characters",
    group=GROUP,
    severity=Severity.MEDIUM,
    mitre=("T1110",),
)
def password_min_length(ctx: SystemContext) -> Outcome:
    pam = ctx.read_text(PAM_PASSWORD)
    if pam is None:
        raise SkipCheck(f"{PAM_PASSWORD} not found")
    line = pwquality_line(pam)
    if line is None:
        return failed("pam_pwquality is not enabled: password strength is not enforced", FIX)
    minlen = effective_minlen(ctx, line)
    detail = f"pam_pwquality minlen = {minlen}"
    if minlen >= REQUIRED_MINLEN:
        return passed(detail)
    return failed(detail, FIX[1:])
