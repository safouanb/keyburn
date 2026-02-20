from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from .config import load_config
from .patterns import Severity
from .sarif import findings_to_sarif
from .scanner import (
    filter_baseline,
    load_baseline,
    save_baseline,
    scan_path,
    should_fail,
    summarize,
)

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


def _get_staged_files(repo_root: Path) -> list[Path]:
    """Return absolute paths of files staged for commit."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        paths = []
        for line in result.stdout.splitlines():
            p = repo_root / line.strip()
            if p.exists():
                paths.append(p)
        return paths
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []


def _get_diff_files(repo_root: Path, base_ref: str) -> list[Path]:
    """Return absolute paths of files changed since base_ref."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACM", base_ref, "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        paths = []
        for line in result.stdout.splitlines():
            p = repo_root / line.strip()
            if p.exists():
                paths.append(p)
        return paths
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), exists=True),
    config: Path | None = typer.Option(None, "--config", help="Path to keyburn.toml"),
    format: str = typer.Option(
        "text", "--format", help="Output format: text|json|sarif", show_default=True
    ),
    out: Path | None = typer.Option(None, "--out", help="Write output to a file"),
    fail_on: Severity = typer.Option(Severity.high, "--fail-on", help="CI fail threshold"),
    baseline: Path | None = typer.Option(
        None,
        "--baseline",
        help="Baseline file of known findings to ignore (JSON).",
    ),
    update_baseline: bool = typer.Option(
        False,
        "--update-baseline",
        help="Write current findings to the baseline file and exit 0.",
    ),
    diff: str | None = typer.Option(
        None,
        "--diff",
        help="Only scan files changed since this git ref (e.g. HEAD~1, main).",
    ),
    pre_commit: bool = typer.Option(
        False,
        "--pre-commit",
        help="Only scan files staged for commit (git diff --cached).",
    ),
) -> None:
    cfg = load_config(config)

    # Resolve which files to scan
    only_files: list[Path] | None = None
    repo_root = path.resolve() if path.is_dir() else path.resolve().parent

    if pre_commit:
        only_files = _get_staged_files(repo_root)
        if not only_files:
            console.print("[dim]No staged files to scan.[/dim]")
            raise typer.Exit(code=0)
    elif diff is not None:
        only_files = _get_diff_files(repo_root, diff)
        if not only_files:
            console.print("[dim]No changed files to scan.[/dim]")
            raise typer.Exit(code=0)

    findings = scan_path(path, cfg=cfg, only_files=only_files)

    # Baseline filtering
    known: set[str] = set()
    if baseline is not None:
        known = load_baseline(baseline)
        findings = filter_baseline(findings, known)

    if update_baseline and baseline is not None:
        # Re-load all findings (un-filtered) to write the full baseline
        all_findings = scan_path(path, cfg=cfg, only_files=only_files)
        save_baseline(all_findings, baseline)
        console.print(
            f"[bold green]Baseline updated:[/bold green] {len(all_findings)} "
            f"fingerprint(s) written to {baseline}"
        )
        raise typer.Exit(code=0)

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
        if known:
            md += f"- Suppressed by baseline: {len(known)} known finding(s)\n"
        _maybe_write_step_summary(md)

    raise typer.Exit(code=1 if should_fail(findings, fail_on=fail_on) else 0)
