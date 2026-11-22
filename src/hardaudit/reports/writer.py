"""Save the report in every file format at once."""

from __future__ import annotations

import json
from pathlib import Path

from hardaudit.reports.html import render_html
from hardaudit.reports.markdown import render_markdown


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)


def write_reports(report: dict, output_dir: Path) -> list[Path]:
    """Write report.json, report.md and report.html; return their paths."""
    output_dir.mkdir(parents=True, exist_ok=True)
    files = {
        "report.json": render_json(report),
        "report.md": render_markdown(report),
        "report.html": render_html(report),
    }
    written = []
    for name, content in files.items():
        path = output_dir / name
        path.write_text(content, encoding="utf-8")
        written.append(path)
    return written
