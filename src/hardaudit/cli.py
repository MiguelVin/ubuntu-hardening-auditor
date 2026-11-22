"""Command line interface: `hardaudit`."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from rich.console import Console

from hardaudit import __version__
from hardaudit.context import SystemContext
from hardaudit.models import Status
from hardaudit.reports.data import build_report
from hardaudit.reports.markdown import render_markdown
from hardaudit.reports.terminal import render_terminal
from hardaudit.reports.writer import render_json, write_reports
from hardaudit.runner import available_groups, run_checks


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hardaudit",
        description="Audit the security hardening of an Ubuntu system.",
        epilog="Exit code: 0 if every evaluated check passed, 1 if any failed.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("/"),
        help="audit a filesystem mounted at this path instead of / (e.g. a container or image)",
    )
    parser.add_argument(
        "--group",
        action="append",
        choices=available_groups(),
        help="only run this group of checks (can be repeated)",
    )
    parser.add_argument(
        "--format",
        choices=["terminal", "json", "markdown"],
        default="terminal",
        help="what to print on screen (default: terminal)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="DIR",
        help="also save report.html, report.md and report.json in this folder",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)  # does not exist on Windows
    return geteuid is not None and geteuid() == 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.root.is_dir():
        parser.error(f"--root is not a directory: {args.root}")

    ctx = SystemContext(args.root)
    results = run_checks(ctx, args.group)
    report = build_report(results, str(args.root))
    console = Console()

    if args.format == "json":
        print(render_json(report))
    elif args.format == "markdown":
        print(render_markdown(report))
    else:
        render_terminal(results, report["score"], console, str(args.root), _is_root())

    if args.output:
        written = write_reports(report, args.output)
        # stderr, so `--format json -o dir > out.json` keeps a clean JSON file
        Console(stderr=True).print(
            "Reports saved: " + ", ".join(str(p) for p in written), highlight=False
        )

    return 1 if any(r.status is Status.FAIL for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
