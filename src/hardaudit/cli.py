"""Command line interface: `hardaudit`."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from rich.console import Console
from rich.rule import Rule

from hardaudit import __version__
from hardaudit.context import SystemContext
from hardaudit.fix.actions import BackupStore, run_all
from hardaudit.fix.engine import plan_fixes
from hardaudit.models import CheckResult, Status
from hardaudit.reports.data import build_report
from hardaudit.reports.markdown import render_markdown
from hardaudit.reports.terminal import render_fix_summary, render_terminal
from hardaudit.reports.writer import render_json, write_reports
from hardaudit.runner import available_groups, run_checks

EXIT_NEEDS_ROOT = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hardaudit",
        description="Audit the security hardening of an Ubuntu system.",
        epilog="Exit code: 0 = all checks passed, 1 = some failed, 2 = --fix needs root.",
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
    parser.add_argument(
        "--screenshot",
        type=Path,
        metavar="FILE.svg",
        help="save the coloured terminal output as an SVG image (for READMEs and posts)",
    )
    parser.add_argument(
        "--no-hints", action="store_true", help="hide the 'How to fix' section (compact output)"
    )
    fix = parser.add_argument_group("automatic fixes")
    fix.add_argument(
        "--fix", action="store_true", help="apply the safe automatic fixes (asks first)"
    )
    fix.add_argument("--dry-run", action="store_true", help="with --fix: only show the plan")
    fix.add_argument("-y", "--yes", action="store_true", help="with --fix: do not ask")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)  # does not exist on Windows
    return geteuid is not None and geteuid() == 0


def _confirm(console: Console) -> bool:
    try:
        answer = console.input("\n[bold]Apply these changes?[/] [y/N] ")
    except EOFError:  # no keyboard (e.g. piped input): never assume yes
        return False
    return answer.strip().lower() in ("y", "yes")


def run_fix(args: argparse.Namespace, results: list[CheckResult], console: Console) -> list:
    """Plan, confirm and apply fixes. Returns the results of a new audit afterwards."""
    ctx = SystemContext(args.root)
    backups = BackupStore()
    plan = plan_fixes(ctx, results, backups)

    console.print(Rule("Automatic fixes"))
    if not args.yes:  # with --yes the applied list below already shows every action
        for action in plan.actions:
            console.print(
                f"  [cyan]•[/] [bold]{action.check_id}[/] {action.description}", highlight=False
            )
    if plan.manual:
        ids = ", ".join(r.meta.id for r in plan.manual)
        console.print(
            f"\n[dim]Not automated (needs a human decision, see 'How to fix'): {ids}[/]",
            highlight=False,
        )
    for check_id, error in plan.errors.items():
        console.print(f"[yellow]Could not plan {check_id}:[/] {error}")
    if not plan.actions:
        console.print("Nothing can be fixed automatically.")
        return results
    if args.dry_run:
        console.print("\n[yellow]Dry run: nothing was changed.[/]")
        return results
    if args.root == Path("/") and not _is_root():
        console.print("\n[bold red]--fix changes system files: run it with sudo.[/]")
        raise SystemExit(EXIT_NEEDS_ROOT)
    if not args.yes and not _confirm(console):
        console.print("Aborted. Nothing was changed.")
        return results

    console.print()
    for item in run_all(plan.actions):
        if item.ok:
            console.print(
                f"  [green]✔[/] {item.action.check_id} {item.action.description}", highlight=False
            )
        else:
            console.print(f"  [red]✘[/] {item.action.check_id} {item.error}", highlight=False)
    if backups.saved:
        console.print("\n[dim]Backups (mode 600):[/]")
        for backup in backups.saved.values():
            console.print(f"  [dim]{ctx.display(backup)}[/]", highlight=False)

    after = run_checks(SystemContext(args.root), args.group)
    render_fix_summary(results, after, console)
    return after


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.root.is_dir():
        parser.error(f"--root is not a directory: {args.root}")
    if (args.dry_run or args.yes) and not args.fix:
        parser.error("--dry-run and --yes only work together with --fix")
    if args.fix and args.format != "terminal":
        parser.error("--fix is interactive: use it with the terminal format")
    if args.screenshot and args.format != "terminal":
        parser.error("--screenshot captures the terminal format")

    results = run_checks(SystemContext(args.root), args.group)
    # record=True keeps everything printed so it can be exported as SVG;
    # a fixed width makes every screenshot the same size.
    console = Console(record=True, width=110) if args.screenshot else Console()

    if args.format == "json":
        print(render_json(build_report(results, str(args.root))))
    elif args.format == "markdown":
        print(render_markdown(build_report(results, str(args.root))))
    else:
        score = build_report(results, str(args.root))["score"]
        render_terminal(
            results, score, console, str(args.root), _is_root(), show_hints=not args.no_hints
        )

    if args.fix:
        results = run_fix(args, results, console)

    if args.output:
        written = write_reports(build_report(results, str(args.root)), args.output)
        # stderr, so `--format json -o dir > out.json` keeps a clean JSON file
        Console(stderr=True).print(
            "Reports saved: " + ", ".join(str(p) for p in written), highlight=False
        )
    if args.screenshot:
        args.screenshot.parent.mkdir(parents=True, exist_ok=True)
        console.save_svg(str(args.screenshot), title="hardaudit")
        Console(stderr=True).print(f"Screenshot saved: {args.screenshot}", highlight=False)

    return 1 if any(r.status is Status.FAIL for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
