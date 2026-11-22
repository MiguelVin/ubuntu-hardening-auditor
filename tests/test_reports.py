import json
from datetime import UTC, datetime

from hardaudit.cli import main
from hardaudit.models import CheckMeta, CheckResult, Severity, Status
from hardaudit.reports.data import build_report, mitre_url
from hardaudit.reports.html import render_html
from hardaudit.reports.markdown import render_markdown

FIXED_TIME = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)


def _report(detail: str = "PermitRootLogin is 'yes'") -> dict:
    results = [
        CheckResult(
            CheckMeta("SSH-001", "Root login disabled", "ssh", Severity.CRITICAL, ("T1110.001",)),
            Status.FAIL,
            detail,
            ["# warning", "sudo do-something"],
        ),
        CheckResult(
            CheckMeta("ACC-001", "Only root UID 0", "accounts", Severity.LOW), Status.PASS, "ok"
        ),
    ]
    return build_report(results, "/", FIXED_TIME)


def test_build_report_summary():
    report = _report()
    assert report["score"] == 9  # 1 / 11
    assert report["grade"] == "Critical"
    assert report["counts"] == {"pass": 1, "fail": 1, "skip": 0, "error": 0}
    assert report["generated_at"] == "2026-11-22T12:00:00+00:00"


def test_mitre_url_for_subtechnique():
    assert mitre_url("T1110.001") == "https://attack.mitre.org/techniques/T1110/001/"


def test_markdown_has_table_fix_section_and_escapes_pipes():
    md = render_markdown(_report(detail="a | b"))
    assert "| ❌ FAIL | SSH-001 | Root login disabled | critical | a \\| b |" in md
    assert "### SSH-001: Root login disabled" in md
    assert "```bash\n# warning\nsudo do-something\n```" in md


def test_html_escapes_untrusted_text():
    html = render_html(_report(detail="<script>alert(1)</script>"))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert 'href="https://attack.mitre.org/techniques/T1110/001/"' in html


def test_cli_output_writes_three_files(tmp_path, capsys):
    root = tmp_path / "root"
    (root / "etc/ssh").mkdir(parents=True)
    (root / "etc/ssh/sshd_config").write_text("PermitRootLogin no\n")
    out = tmp_path / "out"

    main(["--root", str(root), "--group", "ssh", "--format", "json", "-o", str(out)])

    assert sorted(p.name for p in out.iterdir()) == ["report.html", "report.json", "report.md"]
    stdout = capsys.readouterr().out
    assert json.loads(stdout)["target"] == str(root)  # stdout stays valid JSON
