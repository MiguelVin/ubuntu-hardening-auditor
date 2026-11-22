"""Log analysis: evidence of SSH brute force in /var/log/auth.log.

Typical sshd lines:
  sshd[812]: Failed password for root from 203.0.113.7 port 51234 ssh2
  sshd[815]: Invalid user admin from 203.0.113.7 port 51240
"""

from __future__ import annotations

import re
from collections import Counter

from hardaudit.context import SystemContext
from hardaudit.models import Outcome, Severity, SkipCheck, failed, passed
from hardaudit.registry import check

GROUP = "logs"
AUTH_LOG = "/var/log/auth.log"
THRESHOLD = 10  # failed attempts from one IP that we call brute force
TOP = 5

_FAILED = re.compile(
    r"sshd\[\d+\]: (?:Failed password for (?:invalid user )?\S+|Invalid user \S*) from (\S+)"
)


def count_failures(text: str) -> Counter[str]:
    """Failed or invalid SSH login events per source IP."""
    return Counter(m.group(1) for m in _FAILED.finditer(text))


@check(
    id="LOG-001",
    title="No SSH brute-force activity in auth.log",
    group=GROUP,
    severity=Severity.MEDIUM,
    mitre=("T1110.001",),
)
def ssh_brute_force(ctx: SystemContext) -> Outcome:
    text = ctx.read_text(AUTH_LOG)  # readable by root and the "adm" group
    if text is None:
        raise SkipCheck(f"{AUTH_LOG} not found (system may log only to journald)")
    per_ip = count_failures(text)
    total = sum(per_ip.values())
    attackers = [(ip, n) for ip, n in per_ip.most_common() if n >= THRESHOLD]
    if not attackers:
        return passed(f"{total} failed SSH login(s), no IP with {THRESHOLD} or more")
    top = ", ".join(f"{ip} ({n})" for ip, n in attackers[:TOP])
    fix = [
        "# Ban IPs automatically after repeated failures",
        "sudo apt install fail2ban",
        "# Turning off password login (SSH-002) makes guessing useless",
    ]
    fix += [f"sudo ufw deny from {ip}" for ip, _ in attackers[:TOP]]
    return failed(
        f"{total} failed SSH logins; {len(attackers)} IP(s) with {THRESHOLD}+ attempts: {top}",
        fix,
    )
