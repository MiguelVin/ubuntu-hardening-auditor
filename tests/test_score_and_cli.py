import json

from hardaudit.cli import main
from hardaudit.models import CheckMeta, CheckResult, Severity, Status
from hardaudit.score import compute_score, grade


def _result(severity: Severity, status: Status) -> CheckResult:
    return CheckResult(CheckMeta("X", "x", "g", severity), status, "")


def test_score_is_weighted_by_severity():
    results = [
        _result(Severity.CRITICAL, Status.FAIL),  # 10 lost
        _result(Severity.HIGH, Status.PASS),  # 6 gained
        _result(Severity.MEDIUM, Status.PASS),  # 3 gained
        _result(Severity.LOW, Status.PASS),  # 1 gained
    ]
    assert compute_score(results) == 50  # 10 / 20


def test_skips_and_errors_do_not_count():
    results = [_result(Severity.LOW, Status.PASS), _result(Severity.CRITICAL, Status.SKIP)]
    assert compute_score(results) == 100


def test_no_evaluated_checks_gives_no_score():
    assert compute_score([_result(Severity.HIGH, Status.SKIP)]) is None
    assert grade(None) == ("N/A", "white")


def test_cli_json_output_and_exit_code(tmp_path, capsys):
    (tmp_path / "etc/ssh").mkdir(parents=True)
    (tmp_path / "etc/ssh/sshd_config").write_text("PermitRootLogin yes\n")

    exit_code = main(["--root", str(tmp_path), "--group", "ssh", "--format", "json"])

    report = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert report["tool"] == "hardaudit"
    assert {r["id"] for r in report["results"]} == {f"SSH-00{i}" for i in range(1, 6)}
    assert 0 <= report["score"] < 100


def test_cli_terminal_output_runs(tmp_path, capsys):
    (tmp_path / "etc/ssh").mkdir(parents=True)
    (tmp_path / "etc/ssh/sshd_config").write_text("PermitRootLogin no\n")
    main(["--root", str(tmp_path)])
    out = capsys.readouterr().out
    assert "Score:" in out
    assert "SSH-001" in out
