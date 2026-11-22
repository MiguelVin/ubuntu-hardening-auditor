"""Command line interface: `hardaudit`."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from rich.console import Console

from hardaudit import __version__
from hardaudit.context import SystemContext
from hardaudit.models import Status
from hardaudit.reports.terminal import render_terminal
from hardaudit.runner import available_groups, run_checks
from hardaudit.score import compute_score


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
    parser.add_argument("--format", choices=["terminal", "json"], default="terminal")
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
    score = compute_score(results)

    if args.format == "json":
        report = {
            "tool": "hardaudit",
            "version": __version__,
            "root": str(args.root),
            "score": score,
            "evaluated": sum(r.status in (Status.PASS, Status.FAIL) for r in results),
            "total": len(results),
            "results": [r.to_dict() for r in results],
        }
        print(json.dumps(report, indent=2))
    else:
        render_terminal(results, score, Console(), str(args.root), _is_root())

    return 1 if any(r.status is Status.FAIL for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
