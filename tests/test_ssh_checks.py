from conftest import results_by_id

from hardaudit.models import Status

HARDENED = """
    PermitRootLogin no
    PasswordAuthentication no
    PermitEmptyPasswords no
    MaxAuthTries 3
    X11Forwarding no
"""


def test_hardened_config_passes_everything(make_root):
    results = results_by_id(make_root({"/etc/ssh/sshd_config": HARDENED}), "ssh")
    assert {r.status for r in results.values()} == {Status.PASS}


def test_openssh_defaults_are_not_enough(make_root):
    results = results_by_id(make_root({"/etc/ssh/sshd_config": ""}), "ssh")
    assert results["SSH-001"].status is Status.FAIL  # prohibit-password
    assert results["SSH-002"].status is Status.FAIL  # passwords allowed
    assert results["SSH-003"].status is Status.PASS
    assert results["SSH-004"].status is Status.FAIL  # 6 tries
    assert results["SSH-005"].status is Status.PASS
    assert "OpenSSH default" in results["SSH-001"].detail


def test_failed_check_suggests_dropin_fix(make_root):
    results = results_by_id(make_root({"/etc/ssh/sshd_config": "PermitRootLogin yes\n"}), "ssh")
    fix = results["SSH-001"].remediation
    assert "PermitRootLogin no" in fix[0]
    assert "00-hardening.conf" in fix[0]
    assert "sshd -t" in fix[-1]


def test_password_fix_warns_about_lockout(make_root):
    results = results_by_id(make_root({"/etc/ssh/sshd_config": ""}), "ssh")
    assert results["SSH-002"].remediation[0].startswith("# Make sure SSH key login works")


def test_invalid_number_is_reported_as_error(make_root):
    results = results_by_id(make_root({"/etc/ssh/sshd_config": "MaxAuthTries lots\n"}), "ssh")
    assert results["SSH-004"].status is Status.ERROR


def test_without_sshd_every_check_is_skipped(make_root):
    results = results_by_id(make_root({}), "ssh")
    assert {r.status for r in results.values()} == {Status.SKIP}
