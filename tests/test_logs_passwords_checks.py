from conftest import results_by_id

from hardaudit.checks.logs import count_failures
from hardaudit.models import Status

# 203.0.113.0/24 and 198.51.100.0/24 are reserved for documentation (RFC 5737).
ATTACKER = "203.0.113.7"
OTHER = "198.51.100.20"


def _auth_log(attacker_attempts: int, other_attempts: int) -> str:
    lines = []
    for i in range(attacker_attempts):
        user = "root" if i % 2 else "invalid user admin"
        lines.append(
            f"Nov 22 03:1{i % 10}:00 srv sshd[{900 + i}]: "
            f"Failed password for {user} from {ATTACKER} port 5{i} ssh2"
        )
    for i in range(other_attempts):
        lines.append(
            f"Nov 22 04:00:0{i} srv sshd[{700 + i}]: Invalid user test from {OTHER} port 6{i}"
        )
    lines.append(
        "Nov 22 05:00:00 srv sshd[1]: Accepted publickey for miguel from 192.168.0.10 port 1 ssh2"
    )
    return "\n".join(lines) + "\n"


def test_count_failures_ignores_successful_logins():
    counts = count_failures(_auth_log(3, 2))
    assert counts == {ATTACKER: 3, OTHER: 2}


def test_brute_force_detected(make_root):
    ctx = make_root({"/var/log/auth.log": _auth_log(25, 3)})
    result = results_by_id(ctx, "logs")["LOG-001"]
    assert result.status is Status.FAIL
    assert result.detail == f"28 failed SSH logins; 1 IP(s) with 10+ attempts: {ATTACKER} (25)"
    assert f"sudo ufw deny from {ATTACKER}" in result.remediation


def test_few_failures_pass(make_root):
    ctx = make_root({"/var/log/auth.log": _auth_log(4, 2)})
    assert results_by_id(ctx, "logs")["LOG-001"].status is Status.PASS


def test_missing_auth_log_is_skipped(make_root):
    result = results_by_id(make_root({"/etc/hosts": ""}), "logs")["LOG-001"]
    assert result.status is Status.SKIP
    assert "journald" in result.detail


PAM_UBUNTU = "password [success=1 default=ignore] pam_unix.so obscure yescrypt\n"
PAM_PWQUALITY = "password requisite pam_pwquality.so retry=3\n" + PAM_UBUNTU


def test_pwquality_not_installed_fails(make_root):
    ctx = make_root({"/etc/pam.d/common-password": PAM_UBUNTU})
    result = results_by_id(ctx, "passwords")["PWD-001"]
    assert result.status is Status.FAIL
    assert result.remediation[0] == "sudo apt install libpam-pwquality"


def test_pwquality_default_minlen_is_too_short(make_root):
    ctx = make_root({"/etc/pam.d/common-password": PAM_PWQUALITY})
    result = results_by_id(ctx, "passwords")["PWD-001"]
    assert result.detail == "pam_pwquality minlen = 8"
    assert result.status is Status.FAIL


def test_minlen_from_conf_dropin_passes(make_root):
    ctx = make_root(
        {
            "/etc/pam.d/common-password": PAM_PWQUALITY,
            "/etc/security/pwquality.conf": "# minlen = 20\nminlen = 9\n",
            "/etc/security/pwquality.conf.d/60-hardening.conf": "minlen = 14\n",
        }
    )
    assert results_by_id(ctx, "passwords")["PWD-001"].status is Status.PASS


def test_pam_argument_overrides_conf(make_root):
    pam = PAM_PWQUALITY.replace("retry=3", "retry=3 minlen=10")
    ctx = make_root(
        {"/etc/pam.d/common-password": pam, "/etc/security/pwquality.conf": "minlen = 16\n"}
    )
    assert results_by_id(ctx, "passwords")["PWD-001"].detail == "pam_pwquality minlen = 10"
