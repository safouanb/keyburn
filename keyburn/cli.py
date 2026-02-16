from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from .config import load_config
from .patterns import Severity
from .sarif import findings_to_sarif
from .scanner import scan_path, should_fail, summarize

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()

_SEVERITY_STYLE = {
    "high": "bold red",
    "medium": "bold yellow",
    "low": "dim",
}


def _write_text(out: Path | None, text: str) -> None:
    if out is None:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")
        return
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")


def _maybe_write_step_summary(summary_md: str) -> None:
    step_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not step_path:
        return
    try:
        Path(step_path).write_text(summary_md, encoding="utf-8")
    except OSError:
        return


def _print_findings_text(findings: list, summ: dict) -> None:
    if not findings:
        console.print("[bold green]No secrets found.[/bold green]")
        return

    for f in findings:
        sev_style = _SEVERITY_STYLE.get(f.severity.value, "")
        header = f"[{sev_style}]{f.severity.value.upper()}[/{sev_style}]  {f.title}"
        body_lines = [
            f"  File: {f.path}:{f.line}:{f.column}",
            f"  Rule: {f.pattern_id}",
            f"  Match: {f.match_redacted}",
        ]
        if f.remediation:
            body_lines.append("")
            body_lines.append(f"  [bold]How to fix:[/bold] {f.remediation}")

        console.print(
            Panel(
                "\n".join(body_lines),
                title=header,
                title_align="left",
                border_style=sev_style or "dim",
                expand=False,
            )
        )

    console.print()
    console.print(
        f"[bold]Summary:[/bold] {summ['total']} finding(s) — "
        f"[bold red]{summ['high']} high[/bold red], "
        f"[bold yellow]{summ['medium']} medium[/bold yellow], "
        f"{summ['low']} low"
    )


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), exists=True),
    config: Path | None = typer.Option(None, "--config", help="Path to keyburn.toml"),
    format: str = typer.Option(
        "text", "--format", help="Output format: text|json|sarif", show_default=True
    ),
    out: Path | None = typer.Option(None, "--out", help="Write output to a file"),
    fail_on: Severity = typer.Option(Severity.high, "--fail-on", help="CI fail threshold"),
) -> None:
    cfg = load_config(config)
    findings = scan_path(path, cfg=cfg)
    summ = summarize(findings)

    fmt = format.lower().strip()
    if fmt not in {"text", "json", "sarif"}:
        raise typer.BadParameter("format must be one of: text, json, sarif")

    if fmt == "sarif":
        payload = findings_to_sarif(findings)
        _write_text(out, json.dumps(payload, indent=2))
    elif fmt == "json":
        payload = {"summary": summ, "findings": [f.to_dict() for f in findings]}
        _write_text(out, json.dumps(payload, indent=2))
    else:
        _print_findings_text(findings, summ)

        md = (
            "## keyburn\n\n"
            f"- Findings: **{summ['total']}** "
            f"(high={summ['high']}, medium={summ['medium']}, low={summ['low']})\n"
        )
        _maybe_write_step_summary(md)

    raise typer.Exit(code=1 if should_fail(findings, fail_on=fail_on) else 0)
