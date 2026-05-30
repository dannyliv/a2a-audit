"""Renderers: rich table, JSON, and aggregate CSV."""

from __future__ import annotations

import csv
import io
import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from a2a_audit.finding import AuditResult, Severity

_SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_GRADE_STYLE = {"A": "bold green", "B": "green", "C": "yellow", "D": "orange3", "F": "bold red"}


def render_table(result: AuditResult, console: Console | None = None) -> None:
    console = console or Console()
    grade_style = _GRADE_STYLE.get(result.grade, "white")
    header = (
        f"[b]{result.target}[/b]\n"
        f"score [{grade_style}]{result.score}/100  grade {result.grade}[/{grade_style}]   "
        f"spec {result.spec_version}   classifier {result.classifier_mode}"
    )
    if result.fetched_path:
        header += f"   path {result.fetched_path}"
    console.print(Panel(header, title="a2a-audit", expand=False))

    if result.errors:
        for e in result.errors:
            console.print(f"[red]error:[/red] {e}")

    issues = [f for f in result.findings if not f.passed]
    passed = [f for f in result.findings if f.passed]

    if issues:
        table = Table(show_lines=False, expand=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("ASI", no_wrap=True)
        table.add_column("Check", no_wrap=True)
        table.add_column("Finding")
        for f in sorted(issues, key=lambda x: x.severity.rank, reverse=True):
            style = _SEV_STYLE.get(f.severity, "white")
            asi = f.asi_primary.value
            if f.asi_secondary:
                asi += f"/{f.asi_secondary.value}"
            msg = f.title
            if f.evidence:
                msg += f"\n[dim]{f.evidence}[/dim]"
            table.add_row(f"[{style}]{f.severity.value}[/{style}]", asi, f.check_id, msg)
        console.print(table)
    else:
        console.print("[green]No issues found.[/green]")

    if passed:
        names = ", ".join(sorted({f.check_id for f in passed}))
        console.print(f"[green]Passed controls:[/green] {names}")


def render_json(result: AuditResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def aggregate_csv(results: list[AuditResult]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["target", "spec_version", "score", "grade", "max_severity", "num_findings", "classifier_mode"]
    )
    for r in results:
        issues = [f for f in r.findings if not f.passed]
        writer.writerow(
            [
                r.target,
                r.spec_version,
                r.score,
                r.grade,
                r.max_severity().value,
                len(issues),
                r.classifier_mode,
            ]
        )
    return buf.getvalue()


def aggregate_summary(results: list[AuditResult], console: Console | None = None) -> None:
    console = console or Console()
    table = Table(title="Aggregate posture", expand=True)
    table.add_column("Grade", no_wrap=True)
    table.add_column("Count", justify="right")
    by_grade: dict[str, int] = {}
    for r in results:
        by_grade[r.grade] = by_grade.get(r.grade, 0) + 1
    for g in ["A", "B", "C", "D", "F"]:
        if g in by_grade:
            style = _GRADE_STYLE.get(g, "white")
            table.add_row(f"[{style}]{g}[/{style}]", str(by_grade[g]))
    console.print(table)
    if results:
        avg = round(sum(r.score for r in results) / len(results), 1)
        console.print(f"audited [b]{len(results)}[/b] cards, mean score [b]{avg}[/b]/100")
