import os
import stat

import pytest
from conftest import results_by_id

from hardaudit.cli import main
from hardaudit.context import SystemContext
from hardaudit.fix.actions import BackupStore, run_all
from hardaudit.fix.engine import plan_fixes
from hardaudit.models import Status
from hardaudit.runner import run_checks

INSECURE_SSHD = """
    Include /etc/ssh/sshd_config.d/*.conf
    PermitRootLogin yes
    PasswordAuthentication yes
    MaxAuthTries 10
"""


def _fix(ctx: SystemContext, group: str) -> BackupStore:
    """Plan and apply every automatic fix for one group."""
    backups = BackupStore(stamp="test")
    plan = plan_fixes(ctx, run_checks(ctx, [group]), backups)
    assert all(item.ok for item in run_all(plan.actions))
    return backups


def test_ssh_fixes_make_every_ssh_check_pass(make_root):
    ctx = make_root({"/etc/ssh/sshd_config": INSECURE_SSHD})
    _fix(ctx, "ssh")
    results = results_by_id(SystemContext(ctx.root), "ssh")
    assert {r.status for r in results.values()} == {Status.PASS}
    dropin = ctx.path("/etc/ssh/sshd_config.d/00-hardening.conf").read_text()
    assert "PermitRootLogin no" in dropin


def test_file_created_by_the_run_gets_no_backup(make_root):
    # Bug found in the lab: the 2nd SSH fix used to back up the drop-in
    # that the 1st fix had just created, half-written.
    ctx = make_root({"/etc/ssh/sshd_config": INSECURE_SSHD})
    backups = _fix(ctx, "ssh")
    assert backups.saved == {}
    assert not list(ctx.path("/etc/ssh/sshd_config.d").glob("*.bak"))


def test_ssh_fix_adds_include_when_missing(make_root):
    ctx = make_root({"/etc/ssh/sshd_config": "PermitRootLogin yes\n"})
    backups = _fix(ctx, "ssh")
    main_config = ctx.path("/etc/ssh/sshd_config").read_text()
    assert main_config.startswith("Include /etc/ssh/sshd_config.d/*.conf\n")
    assert (
        ctx.path("/etc/ssh/sshd_config.hardaudit-test.bak").read_text() == "PermitRootLogin yes\n"
    )
    assert ctx.path("/etc/ssh/sshd_config") in backups.saved


def test_ssh_fix_replaces_previous_value_in_dropin(make_root):
    ctx = make_root(
        {
            "/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\n",
            "/etc/ssh/sshd_config.d/00-hardening.conf": "maxauthtries 9\n",
        }
    )
    _fix(ctx, "ssh")
    dropin = ctx.path("/etc/ssh/sshd_config.d/00-hardening.conf").read_text()
    assert "maxauthtries 9" not in dropin
    assert dropin.count("MaxAuthTries 4") == 1


def test_passwordless_account_is_locked_and_backup_is_private(make_root):
    ctx = make_root({"/etc/shadow": "root:!:1::::::\nguest::1::::::\n"})
    os.chmod(ctx.path("/etc/shadow"), 0o644)
    _fix(ctx, "accounts")
    assert ctx.path("/etc/shadow").read_text() == "root:!:1::::::\nguest:!:1::::::\n"
    backup = ctx.path("/etc/shadow.hardaudit-test.bak")
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600  # never as open as the original
    assert stat.S_IMODE(ctx.path("/etc/shadow").stat().st_mode) == 0o644  # mode kept


def test_accounts_needing_a_decision_are_not_automated(make_root):
    ctx = make_root(
        {
            "/etc/passwd": "root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/root:/bin/bash\n",
            "/etc/sudoers": "deploy ALL=(ALL) NOPASSWD: ALL\n",
        }
    )
    plan = plan_fixes(ctx, run_checks(ctx, ["accounts"]), BackupStore())
    assert plan.actions == []
    assert {r.meta.id for r in plan.manual} == {"ACC-001", "ACC-003"}


def test_world_writable_and_gtfobins_suid_are_fixed(make_root):
    ctx = make_root({"/etc/app.ini": "", "/usr/bin/find": "", "/usr/bin/weird": ""})
    os.chmod(ctx.path("/etc/app.ini"), 0o666)
    os.chmod(ctx.path("/usr/bin/find"), 0o4755)
    os.chmod(ctx.path("/usr/bin/weird"), 0o4755)
    _fix(ctx, "permissions")
    assert stat.S_IMODE(ctx.path("/etc/app.ini").stat().st_mode) == 0o664
    assert stat.S_IMODE(ctx.path("/usr/bin/find").stat().st_mode) == 0o755
    # Unknown SUID program: may really need it, so a human decides
    assert stat.S_IMODE(ctx.path("/usr/bin/weird").stat().st_mode) == 0o4755


def test_password_minlen_fix(make_root):
    pam = "password requisite pam_pwquality.so retry=3\n"
    ctx = make_root({"/etc/pam.d/common-password": pam})
    _fix(ctx, "passwords")
    result = results_by_id(SystemContext(ctx.root), "passwords")["PWD-001"]
    assert result.status is Status.PASS


def test_password_fix_skipped_when_pwquality_missing(make_root):
    ctx = make_root({"/etc/pam.d/common-password": "password required pam_unix.so\n"})
    plan = plan_fixes(ctx, run_checks(ctx, ["passwords"]), BackupStore())
    assert plan.actions == []


def test_cli_dry_run_changes_nothing(make_root, capsys):
    ctx = make_root({"/etc/ssh/sshd_config": INSECURE_SSHD})
    before = ctx.path("/etc/ssh/sshd_config").read_text()
    main(["--root", str(ctx.root), "--group", "ssh", "--fix", "--dry-run"])
    out = capsys.readouterr().out
    assert "Dry run: nothing was changed" in out
    assert ctx.path("/etc/ssh/sshd_config").read_text() == before
    assert not ctx.path("/etc/ssh/sshd_config.d/00-hardening.conf").exists()


def test_cli_fix_yes_applies_and_reports_new_score(make_root, capsys):
    ctx = make_root({"/etc/ssh/sshd_config": INSECURE_SSHD})
    exit_code = main(["--root", str(ctx.root), "--group", "ssh", "--fix", "--yes"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "→ 100/100" in out


def test_cli_fix_rejects_json_format(make_root):
    ctx = make_root({"/etc/hosts": ""})
    with pytest.raises(SystemExit):
        main(["--root", str(ctx.root), "--fix", "--format", "json"])
