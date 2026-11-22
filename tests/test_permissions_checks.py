import os
from types import SimpleNamespace

import pytest
from conftest import results_by_id

from hardaudit.models import Status


@pytest.fixture
def root_owned(monkeypatch):
    """Pretend every file is owned by root (files in tmp belong to the test user)."""

    def apply(ctx):
        original = ctx.stat

        def fake_stat(path):
            info = original(path)
            return None if info is None else SimpleNamespace(st_mode=info.st_mode, st_uid=0)

        monkeypatch.setattr(ctx, "stat", fake_stat)
        return ctx

    return apply


ACCOUNT_FILES = {"/etc/passwd": "", "/etc/group": "", "/etc/shadow": "", "/etc/gshadow": ""}


def _chmod(ctx, path, mode):
    os.chmod(ctx.path(path), mode)


def test_correct_account_file_permissions_pass(make_root, root_owned):
    ctx = root_owned(make_root(ACCOUNT_FILES))
    _chmod(ctx, "/etc/shadow", 0o640)
    _chmod(ctx, "/etc/gshadow", 0o600)  # more restrictive is fine
    result = results_by_id(ctx, "permissions")["PERM-001"]
    assert result.status is Status.PASS


def test_world_readable_shadow_fails(make_root, root_owned):
    ctx = root_owned(make_root(ACCOUNT_FILES))
    _chmod(ctx, "/etc/shadow", 0o644)
    _chmod(ctx, "/etc/gshadow", 0o640)
    result = results_by_id(ctx, "permissions")["PERM-001"]
    assert result.status is Status.FAIL
    assert result.detail == "/etc/shadow: mode 644 (max 640)"
    assert result.remediation == ["sudo chown root /etc/shadow && sudo chmod 640 /etc/shadow"]


def test_file_not_owned_by_root_fails(make_root):
    ctx = make_root({"/etc/passwd": ""})  # owned by the test user
    _chmod(ctx, "/etc/passwd", 0o644)
    result = results_by_id(ctx, "permissions")["PERM-001"]
    assert result.status is Status.FAIL
    assert "expected root" in result.detail


def test_world_writable_file_in_etc_fails_but_symlinks_are_ignored(make_root):
    ctx = make_root({"/etc/hosts": "", "/etc/app/config.ini": ""})
    _chmod(ctx, "/etc/app/config.ini", 0o666)
    os.symlink("/etc/hosts", ctx.path("/etc/hosts-link"))
    result = results_by_id(ctx, "permissions")["PERM-002"]
    assert result.status is Status.FAIL
    assert result.detail == "World-writable: /etc/app/config.ini"
    assert result.remediation == ["sudo chmod o-w /etc/app/config.ini"]


def test_sticky_world_writable_directory_is_allowed(make_root):
    ctx = make_root({"/etc/hosts": ""})
    os.mkdir(ctx.path("/etc/shared"))
    _chmod(ctx, "/etc/shared", 0o1777)
    assert results_by_id(ctx, "permissions")["PERM-002"].status is Status.PASS


def test_expected_suid_passes_unknown_and_gtfobins_fail(make_root):
    ctx = make_root({"/usr/bin/passwd": "", "/usr/bin/find": "", "/usr/bin/python3.14": ""})
    _chmod(ctx, "/usr/bin/passwd", 0o4755)
    assert results_by_id(ctx, "permissions")["PERM-003"].status is Status.PASS

    _chmod(ctx, "/usr/bin/find", 0o4755)
    _chmod(ctx, "/usr/bin/python3.14", 0o2755)  # SGID counts too
    result = results_by_id(ctx, "permissions")["PERM-003"]
    assert result.status is Status.FAIL
    assert "/usr/bin/find [GTFOBins: root shell]" in result.detail
    assert "/usr/bin/python3.14 [GTFOBins: root shell]" in result.detail
    assert "sudo chmod u-s,g-s /usr/bin/find" in result.remediation


def test_classic_sudo_on_new_ubuntu_is_expected(make_root):
    # Found on a real Ubuntu 26.04: sudo-rs is "sudo", the classic one is "sudo.ws".
    ctx = make_root({"/usr/bin/sudo.ws": ""})
    _chmod(ctx, "/usr/bin/sudo.ws", 0o4755)
    assert results_by_id(ctx, "permissions")["PERM-003"].status is Status.PASS


def test_bin_symlink_to_usr_bin_is_scanned_once(make_root):
    ctx = make_root({"/usr/bin/evil": ""})
    _chmod(ctx, "/usr/bin/evil", 0o4755)
    os.symlink("usr/bin", ctx.path("/bin"))  # like Ubuntu: /bin -> usr/bin
    result = results_by_id(ctx, "permissions")["PERM-003"]
    assert result.detail == "Unexpected SUID/SGID: /usr/bin/evil"
