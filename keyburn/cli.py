from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .config import load_config
from .patterns import Severity
from .sarif import findings_to_sarif
from .scanner import scan_path, should_fail, summarize


app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()


def _write_text(out: Optional[Path], text: str) -> None:
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


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), exists=True),
    config: Optional[Path] = typer.Option(None, "--config", help="Path to keyburn.toml"),
    format: str = typer.Option(
        "text", "--format", help="Output format: text|json|sarif", show_default=True
    ),
    out: Optional[Path] = typer.Option(None, "--out", help="Write output to a file"),
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
        table = Table(title="keyburn findings", show_lines=False)
        table.add_column("Severity", style="bold")
        table.add_column("File")
        table.add_column("Line", justify="right")
        table.add_column("Rule")
        table.add_column("Match")
        for f in findings:
            table.add_row(
                f.severity.value,
                f.path,
                str(f.line),
                f.pattern_id,
                f.match_redacted,
            )

        console.print(table)
        console.print(
            f"[bold]Summary[/bold] total={summ['total']} high={summ['high']} medium={summ['medium']} low={summ['low']}"
        )

        md = (
            "## keyburn\n\n"
            f"- Findings: **{summ['total']}** (high={summ['high']}, medium={summ['medium']}, low={summ['low']})\n"
        )
        _maybe_write_step_summary(md)

    raise typer.Exit(code=1 if should_fail(findings, fail_on=fail_on) else 0)
