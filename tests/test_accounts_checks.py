from conftest import results_by_id

from hardaudit.models import Status

PASSWD = """
    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    miguel:x:1000:1000:Miguel:/home/miguel:/bin/bash
"""

SHADOW_OK = """
    root:!:19000:0:99999:7:::
    daemon:*:19000:0:99999:7:::
    miguel:$6$salt$hash:19000:0:99999:7:::
"""


def test_clean_accounts_pass(make_root):
    ctx = make_root(
        {
            "/etc/passwd": PASSWD,
            "/etc/shadow": SHADOW_OK,
            "/etc/sudoers": "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n",
        }
    )
    results = results_by_id(ctx, "accounts")
    assert {r.status for r in results.values()} == {Status.PASS}


def test_second_uid_zero_account_fails(make_root):
    ctx = make_root({"/etc/passwd": PASSWD + "toor:x:0:0::/root:/bin/bash\n"})
    result = results_by_id(ctx, "accounts")["ACC-001"]
    assert result.status is Status.FAIL
    assert "toor" in result.detail
    assert "sudo usermod -L -e 1 toor" in result.remediation


def test_empty_password_fails_but_locked_accounts_pass(make_root):
    ctx = make_root({"/etc/shadow": SHADOW_OK + "guest::19000:0:99999:7:::\n"})
    result = results_by_id(ctx, "accounts")["ACC-002"]
    assert result.status is Status.FAIL
    assert result.detail == "Accounts without a password: guest"


def test_unreadable_shadow_is_skipped_with_sudo_hint(make_root, monkeypatch):
    ctx = make_root({"/etc/shadow": SHADOW_OK})
    original = ctx.read_text

    def deny_shadow(path):
        if path == "/etc/shadow":
            raise PermissionError(13, "Permission denied", "/etc/shadow")
        return original(path)

    monkeypatch.setattr(ctx, "read_text", deny_shadow)
    result = results_by_id(ctx, "accounts")["ACC-002"]
    assert result.status is Status.SKIP
    assert "sudo" in result.detail


def test_nopasswd_in_dropin_fails_with_location(make_root):
    ctx = make_root(
        {
            "/etc/sudoers": "# deploy ALL=(ALL) NOPASSWD: ALL\nroot ALL=(ALL:ALL) ALL\n",
            "/etc/sudoers.d/deploy": "# CI deploy user\ndeploy ALL=(ALL) NOPASSWD: ALL\n",
            # sudo ignores names with a dot or ending in "~", so these must be ignored too
            "/etc/sudoers.d/old.bak": "x ALL=(ALL) NOPASSWD: ALL\n",
            "/etc/sudoers.d/deploy~": "y ALL=(ALL) NOPASSWD: ALL\n",
        }
    )
    result = results_by_id(ctx, "accounts")["ACC-003"]
    assert result.status is Status.FAIL
    assert result.detail == "NOPASSWD found at /etc/sudoers.d/deploy:2"
    assert result.remediation == [
        "sudo visudo -f /etc/sudoers.d/deploy  # remove NOPASSWD on line 2"
    ]


def test_missing_files_are_skipped(make_root):
    results = results_by_id(make_root({}), "accounts")
    assert {r.status for r in results.values()} == {Status.SKIP}
