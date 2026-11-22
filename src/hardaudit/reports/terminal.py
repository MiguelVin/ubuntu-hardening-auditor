"""Coloured terminal report (the one that goes into screenshots)."""

from __future__ import annotations

from collections import Counter

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from hardaudit.models import CheckResult, Severity, Status
from hardaudit.score import compute_score, grade

STATUS_STYLE = {
    Status.PASS: ("PASS", "bold green"),
    Status.FAIL: ("FAIL", "bold red"),
    Status.SKIP: ("SKIP", "yellow"),
    Status.ERROR: ("ERROR", "bold magenta"),
}

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}


def render_terminal(
    results: list[CheckResult],
    score: int | None,
    console: Console,
    target: str,
    is_root: bool,
    show_hints: bool = True,
) -> None:
    console.print(Rule("[bold]hardaudit[/] · Ubuntu security audit"))
    privileges = "root" if is_root else "normal user (some checks need sudo)"
    console.print(f"Target: [bold]{target}[/]   Privileges: {privileges}\n", highlight=False)

    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("ID", no_wrap=True, style="dim")
    table.add_column("Check", ratio=2)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Detail", ratio=3, overflow="fold")
    for r in results:
        label, style = STATUS_STYLE[r.status]
        table.add_row(
            Text(label, style=style),
            r.meta.id,
            r.meta.title,
            Text(r.meta.severity.label, style=SEVERITY_STYLE[r.meta.severity]),
            Text(r.detail),  # Text() so brackets in details are not read as markup
        )
    console.print(table)

    failures = [r for r in results if r.status is Status.FAIL]
    if failures and show_hints:
        console.print(Rule("How to fix"))
        for r in failures:
            console.print(f"\n[bold red]{r.meta.id}[/] {r.meta.title}", highlight=False)
            for line in r.remediation:
                if line.startswith("#"):
                    console.print(Text(f"  {line}", style="dim"))
                else:
                    console.print(Text(f"  $ {line}", style="cyan"))
        console.print()

    counts = Counter(r.status for r in results)
    summary = "  ".join(
        f"[{style}]{counts[status]} {label}[/]" for status, (label, style) in STATUS_STYLE.items()
    )
    label, colour = grade(score)
    score_text = "N/A" if score is None else f"{score}/100"
    evaluated = counts[Status.PASS] + counts[Status.FAIL]
    coverage = f"Coverage: {evaluated}/{len(results)} checks evaluated"
    if results and evaluated / len(results) < 0.5:
        # A high score over few checks proves little, so say it out loud.
        coverage = f"[bold yellow]{coverage} (low: the score is not reliable)[/]"
    console.print(
        Panel(
            f"[bold {colour}]Score: {score_text}  ·  {label}[/]\n{summary}\n{coverage}",
            border_style=colour,
            expand=False,
        )
    )
    if counts[Status.SKIP] and not is_root:
        console.print("[yellow]Tip:[/] run with sudo to evaluate the skipped checks.")


def render_fix_summary(
    before: list[CheckResult], after: list[CheckResult], console: Console
) -> None:
    """What changed after --fix: per-check status changes and the new score."""
    console.print(Rule("After fixes"))
    previous = {r.meta.id: r.status for r in before}
    for r in after:
        old = previous.get(r.meta.id)
        if old is not None and old is not r.status:
            old_label, old_style = STATUS_STYLE[old]
            new_label, new_style = STATUS_STYLE[r.status]
            console.print(
                Text.assemble(
                    f"  {r.meta.id:<9}",
                    (old_label, old_style),
                    " → ",
                    (new_label, new_style),
                    f"  {r.meta.title}",
                )
            )

    old_score, new_score = compute_score(before), compute_score(after)
    label, colour = grade(new_score)
    console.print(
        Panel(
            f"[bold {colour}]Score: {old_score} → {new_score}/100  ·  {label}[/]",
            border_style=colour,
            expand=False,
        )
    )
    still = [r.meta.id for r in after if r.status is Status.FAIL]
    if still:
        console.print(
            f"[yellow]Still failing, needs a human decision:[/] {', '.join(still)}. "
            "See 'How to fix' above.",
            highlight=False,
        )
