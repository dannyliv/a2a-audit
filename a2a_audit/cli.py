"""a2a-audit command-line interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console

from a2a_audit import __version__
from a2a_audit.audit import audit_raw, audit_target
from a2a_audit.backends import BackendConfig
from a2a_audit.classifier import SkillClassifier
from a2a_audit.fetch import FetchError, fetch_card
from a2a_audit.finding import AuditResult, Severity
from a2a_audit.report import aggregate_csv, aggregate_summary, render_json, render_table

app = typer.Typer(
    add_completion=False,
    help="Security-posture auditor for A2A Agent Cards (OWASP ASI 2026).",
)

_SEVERITIES = {s.value for s in Severity}


def _version_cb(value: bool) -> None:
    if value:
        typer.echo(f"a2a-audit {__version__}")
        raise typer.Exit()


def _build_classifier(
    backend: str, backend_url: str | None, backend_model: str | None
) -> SkillClassifier:
    cfg = BackendConfig.from_env(override=backend)
    if backend_url:
        cfg.openai_base_url = backend_url
    if backend_model:
        cfg.model = backend_model  # build_backend interprets per selected backend
    classifier = SkillClassifier(mode=backend, config=cfg)
    if classifier.is_degraded:
        import sys

        print(
            "hint: classifier fell back to heuristic (no model available)."
            " Run `a2a-audit-pull-models` to fetch the default local models.",
            file=sys.stderr,
        )
    return classifier


def _exit_code(results: list[AuditResult], fail_on: Severity) -> int:
    for r in results:
        if r.errors:
            return 2
        if any((not f.passed) and f.severity >= fail_on for f in r.findings):
            return 1
    return 0


@app.command()
def main(
    target: str | None = typer.Argument(None, help="URL or domain of the agent to audit."),
    paste: bool = typer.Option(False, "--paste", help="Read a card JSON from stdin (offline)."),
    url: str | None = typer.Option(None, "--url", help="Explicit card/agent URL to audit."),
    registry: bool = typer.Option(False, "--registry", help="Audit cards from a2aregistry.org."),
    limit: int = typer.Option(20, "--limit", help="Number of registry cards to audit."),
    json_out: bool = typer.Option(False, "--json", help="Emit machine JSON to stdout."),
    fail_on: str = typer.Option("HIGH", "--fail-on", help="Min severity for non-zero exit (INFO..CRITICAL)."),
    backend: str = typer.Option(
        "auto",
        "--backend",
        help="Skill classifier backend: auto|heuristic|deberta|gguf|openai|claude|disabled.",
    ),
    backend_url: str | None = typer.Option(
        None, "--backend-url", help="OpenAI-compatible base URL (e.g. http://localhost:11434/v1)."
    ),
    backend_model: str | None = typer.Option(
        None, "--backend-model", help="Model name (openai/claude) or GGUF path (gguf)."
    ),
    classifier_mode: str | None = typer.Option(
        None, "--classifier", hidden=True, help="Deprecated alias for --backend."
    ),
    no_verify_sigs: bool = typer.Option(False, "--no-verify-sigs", help="Skip signature verification."),
    no_refetch: bool = typer.Option(
        False, "--no-refetch", help="Registry: audit embedded card, skip canonical re-fetch."
    ),
    out: str | None = typer.Option(None, "--out", help="Write report JSON to this path."),
    _version: bool = typer.Option(
        False, "--version", callback=_version_cb, is_eager=True, help="Show version and exit."
    ),
) -> None:
    fail_on = fail_on.upper()
    if fail_on not in _SEVERITIES:
        typer.echo(f"invalid --fail-on '{fail_on}'; choose from {sorted(_SEVERITIES)}", err=True)
        raise typer.Exit(2)
    fail_sev = Severity(fail_on)

    # stdout stays pure JSON when --json; human output goes to stderr.
    out_console = Console(stderr=True) if json_out else Console()
    selected_backend = classifier_mode or backend  # --classifier is a deprecated alias
    classifier = _build_classifier(selected_backend, backend_url, backend_model)
    verify_sigs = not no_verify_sigs

    if registry:
        results = _run_registry(limit, classifier, verify_sigs, no_refetch, out_console)
    else:
        single = _run_single(target, url, paste, classifier, verify_sigs, out_console)
        results = [single] if single else []

    if not results:
        raise typer.Exit(2)

    # Output.
    if json_out:
        payload = results[0].to_dict() if len(results) == 1 else [r.to_dict() for r in results]
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    else:
        for r in results:
            render_table(r, out_console)
        if len(results) > 1:
            aggregate_summary(results, out_console)

    # File artifacts.
    if len(results) == 1 and not registry:
        report_path = Path(out) if out else Path("a2a-audit-report.json")
        report_path.write_text(render_json(results[0]) + "\n", encoding="utf-8")
        out_console.print(f"[dim]wrote {report_path}[/dim]")
    elif registry:
        json_path = Path(out) if out else Path("a2a-audit-corpus.json")
        json_path.write_text(
            json.dumps([r.to_dict() for r in results], indent=2) + "\n", encoding="utf-8"
        )
        csv_path = json_path.with_suffix(".csv")
        csv_path.write_text(aggregate_csv(results), encoding="utf-8")
        out_console.print(f"[dim]wrote {json_path} and {csv_path}[/dim]")

    raise typer.Exit(_exit_code(results, fail_sev))


def _run_single(
    target: str | None,
    url: str | None,
    paste: bool,
    classifier: SkillClassifier,
    verify_sigs: bool,
    console: Console,
) -> AuditResult | None:
    if paste:
        data = sys.stdin.read()
        try:
            raw = json.loads(data)
        except json.JSONDecodeError as exc:
            console.print(f"[red]invalid JSON on stdin:[/red] {exc}")
            return None
        if not isinstance(raw, dict):
            console.print("[red]pasted card must be a JSON object[/red]")
            return None
        return audit_raw(
            raw,
            target="(stdin)",
            fetched_https=None,
            classifier=classifier,
            verify_signatures=verify_sigs,
        )

    tgt = url or target
    if not tgt:
        console.print("[red]provide a target URL/domain, --url, --paste, or --registry[/red]")
        return None
    return audit_target(tgt, classifier=classifier, verify_signatures=verify_sigs)


def _run_registry(
    limit: int,
    classifier: SkillClassifier,
    verify_sigs: bool,
    no_refetch: bool,
    console: Console,
) -> list[AuditResult]:
    from a2a_audit.registry import RegistryClient

    results: list[AuditResult] = []
    with RegistryClient() as client:
        try:
            stats = client.stats()
            console.print(f"[dim]registry reports {stats.get('total_agents', '?')} agents[/dim]")
        except Exception:  # noqa: BLE001, S110 - stats line is best-effort cosmetic
            pass
        for agent in client.iter_agents(total=limit):
            label = agent.name or agent.id or "(unknown)"
            tgt = agent.discovery_target()
            if no_refetch or not tgt:
                results.append(
                    audit_raw(
                        agent.embedded,
                        target=f"registry:{label}",
                        fetched_https=None,
                        classifier=classifier,
                        verify_signatures=verify_sigs,
                    )
                )
                continue
            try:
                fetched = fetch_card(tgt)
                results.append(
                    audit_raw(
                        fetched.raw,
                        target=tgt,
                        fetched_https=fetched.transport_https,
                        fetched_path=fetched.path,
                        classifier=classifier,
                        verify_signatures=verify_sigs,
                    )
                )
            except FetchError as exc:
                results.append(
                    AuditResult(
                        target=tgt,
                        parse_ok=False,
                        classifier_mode=classifier.mode,
                        errors=[f"canonical re-fetch failed: {exc}"],
                    )
                )
    return results


if __name__ == "__main__":
    app()
