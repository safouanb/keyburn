from __future__ import annotations

# ruff: noqa: UP045
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

from .config import load_config
from .history import parse_diff_hunks, scan_history
from .patterns import Severity
from .redact import redact
from .sarif import findings_to_sarif
from .scanner import (
    filter_baseline,
    load_baseline,
    save_baseline,
    scan_added_lines,
    scan_path,
    should_fail,
    summarize,
)
from .verify import SUPPORTED_PROVIDERS, VerificationResult, verify_secret

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()

_SEVERITY_STYLE = {
    "high": "bold red",
    "medium": "bold yellow",
    "low": "dim",
}

_VERIFY_STATUS_STYLE = {
    "valid": "bold red",
    "invalid": "bold green",
    "unknown": "bold yellow",
    "error": "bold yellow",
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


def _print_findings_text(
    findings: list,
    summ: dict,
    history_lookup: dict[str, dict[str, str]] | None = None,
) -> None:
    if not findings:
        console.print("[bold green]No secrets found.[/bold green]")
        return

    for f in findings:
        sev_style = _SEVERITY_STYLE.get(f.severity.value, "")
        header = f"[{sev_style}]{f.severity.value.upper()}[/{sev_style}]  {f.title}"
        body_lines = [
            f"  File: {f.path}:{f.line}:{f.column}",
            f"  Rule: {f.pattern_id}",
            f"  Provider: {getattr(f, 'provider', 'unknown')}",
            f"  Risk: {getattr(f, 'risk_score', 0)}/100",
            f"  Match: {f.match_redacted}",
        ]
        risk_factors = getattr(f, "risk_factors", ())
        if risk_factors:
            body_lines.append(f"  Signals: {', '.join(risk_factors)}")
        if history_lookup and f.fingerprint in history_lookup:
            commit = history_lookup[f.fingerprint]
            body_lines.append(f"  Commit: {commit.get('sha', '')[:8]} ({commit.get('date', '')})")
            if commit.get("subject"):
                body_lines.append(f"  Subject: {commit['subject']}")

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


def _print_verify_text(result: VerificationResult, redacted_secret: str) -> None:
    status_style = _VERIFY_STATUS_STYLE.get(result.status, "bold")
    status_label = f"[{status_style}]{result.status.upper()}[/{status_style}]"

    body_lines = [
        f"  Provider: {result.provider}",
        f"  Status: {status_label}",
        f"  Confidence: {result.confidence}/100",
        f"  Priority: {result.priority}",
        f"  Secret: {redacted_secret}",
        f"  Reason: {result.reason}",
    ]
    if result.http_status is not None:
        body_lines.insert(5, f"  HTTP: {result.http_status}")

    console.print(
        Panel(
            "\n".join(body_lines),
            title="[bold]keyburn verify[/bold]",
            title_align="left",
            border_style=status_style,
            expand=False,
        )
    )


def _parse_history_arg(value: str) -> int | None:
    """
    Parse --history value.
    - "all" => None (full history)
    - positive integer => number of commits
    """
    raw = value.strip().lower()
    if raw == "all":
        return None
    try:
        parsed = int(raw)
    except ValueError as exc:
        raise typer.BadParameter("--history must be a positive integer or 'all'") from exc

    if parsed <= 0:
        raise typer.BadParameter("--history must be a positive integer or 'all'")
    return parsed


def _get_changed_lines(repo_root: Path, git_args: list[str]) -> dict[str, list[tuple[int, str]]]:
    """Return changed (added) lines grouped by relative file path."""
    try:
        result = subprocess.run(
            ["git", *git_args],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        grouped: dict[str, list[tuple[int, str]]] = {}
        for rel_path, line_no, content in parse_diff_hunks(result.stdout):
            if not rel_path:
                continue
            grouped.setdefault(rel_path, []).append((line_no, content))
        return grouped
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {}


def _filter_changed_lines_to_target(
    changed_lines: dict[str, list[tuple[int, str]]],
    *,
    repo_root: Path,
    target: Path,
) -> dict[str, list[tuple[int, str]]]:
    """Limit diff findings to the user-requested path argument."""
    target_abs = target.resolve()
    out: dict[str, list[tuple[int, str]]] = {}

    for rel_path, lines in changed_lines.items():
        abs_path = (repo_root / rel_path).resolve()
        if target_abs.is_file():
            if abs_path != target_abs:
                continue
        else:
            try:
                abs_path.relative_to(target_abs)
            except ValueError:
                continue
        out[rel_path] = lines

    return out


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), exists=True),
    config: Optional[Path] = typer.Option(None, "--config", help="Path to keyburn.toml"),
    format: str = typer.Option(
        "text", "--format", help="Output format: text|json|sarif", show_default=True
    ),
    out: Optional[Path] = typer.Option(None, "--out", help="Write output to a file"),
    fail_on: Severity = typer.Option(Severity.high, "--fail-on", help="CI fail threshold"),
    baseline: Optional[Path] = typer.Option(
        None,
        "--baseline",
        help="Baseline file of known findings to ignore (JSON).",
    ),
    update_baseline: bool = typer.Option(
        False,
        "--update-baseline",
        help="Write current findings to the baseline file and exit 0.",
    ),
    diff: Optional[str] = typer.Option(
        None,
        "--diff",
        help="Only scan added lines changed since this git ref (e.g. HEAD~1, main).",
    ),
    history: Optional[str] = typer.Option(
        None,
        "--history",
        help="Scan git history. Use a commit count (e.g. 50) or 'all'.",
    ),
    pre_commit: bool = typer.Option(
        False,
        "--pre-commit",
        help="Only scan added lines staged for commit (git diff --cached).",
    ),
) -> None:
    mode_count = int(pre_commit) + int(diff is not None) + int(history is not None)
    if mode_count > 1:
        raise typer.BadParameter("Use only one of --pre-commit, --diff, or --history.")

    cfg = load_config(config)

    # Resolve scan mode
    target_path = path.resolve()
    repo_root = target_path if target_path.is_dir() else target_path.parent
    history_lookup: dict[str, dict[str, str]] = {}

    if history is not None:
        max_commits = _parse_history_arg(history)
        history_findings = scan_history(repo_root, max_commits=max_commits, cfg=cfg)
        all_findings = [hf.finding for hf in history_findings]
        history_lookup = {
            hf.finding.fingerprint: {
                "sha": hf.commit.sha,
                "date": hf.commit.date,
                "author": hf.commit.author,
                "subject": hf.commit.subject,
            }
            for hf in history_findings
        }
    else:
        if pre_commit:
            changed_lines = _get_changed_lines(
                repo_root,
                ["diff", "--cached", "--unified=0", "--diff-filter=ACM"],
            )
            changed_lines = _filter_changed_lines_to_target(
                changed_lines,
                repo_root=repo_root,
                target=target_path,
            )
            if not changed_lines:
                console.print("[dim]No staged added lines to scan.[/dim]")
                raise typer.Exit(code=0)
            all_findings = scan_added_lines(files=changed_lines, root=repo_root, cfg=cfg)
        elif diff is not None:
            changed_lines = _get_changed_lines(
                repo_root,
                ["diff", "--unified=0", "--diff-filter=ACM", diff, "HEAD"],
            )
            changed_lines = _filter_changed_lines_to_target(
                changed_lines,
                repo_root=repo_root,
                target=target_path,
            )
            if not changed_lines:
                console.print("[dim]No changed added lines to scan.[/dim]")
                raise typer.Exit(code=0)
            all_findings = scan_added_lines(files=changed_lines, root=repo_root, cfg=cfg)
        else:
            all_findings = scan_path(path, cfg=cfg)

    findings = all_findings

    # Baseline filtering
    known: set[str] = set()
    if baseline is not None:
        known = load_baseline(baseline)
        findings = filter_baseline(findings, known)

    if update_baseline and baseline is not None:
        # Write baseline from unfiltered findings in the selected mode.
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
        if history_lookup:
            payload["history"] = [
                {
                    "fingerprint": f.fingerprint,
                    "commit": history_lookup.get(f.fingerprint, {}),
                }
                for f in findings
            ]
        _write_text(out, json.dumps(payload, indent=2))
    else:
        _print_findings_text(findings, summ, history_lookup=history_lookup or None)

        md = (
            "## keyburn\n\n"
            f"- Findings: **{summ['total']}** "
            f"(high={summ['high']}, medium={summ['medium']}, low={summ['low']})\n"
        )
        if history is not None:
            hist_label = "all" if _parse_history_arg(history) is None else history
            md += f"- Mode: git history ({hist_label} commit(s))\n"
        elif pre_commit:
            md += "- Mode: pre-commit (added lines only)\n"
        elif diff is not None:
            md += f"- Mode: diff from {diff} (added lines only)\n"
        if known:
            md += f"- Suppressed by baseline: {len(known)} known finding(s)\n"
        _maybe_write_step_summary(md)

    raise typer.Exit(code=1 if should_fail(findings, fail_on=fail_on) else 0)


@app.command()
def verify(
    secret: Optional[str] = typer.Argument(
        None,
        help="Secret/token value to verify. Prefer --from-env to avoid shell history leaks.",
    ),
    provider: str = typer.Option(
        "auto",
        "--provider",
        help="Provider to verify against: auto|anthropic|github|groq|openai|stripe",
        show_default=True,
    ),
    from_env: Optional[str] = typer.Option(
        None,
        "--from-env",
        help="Read the secret value from this environment variable.",
    ),
    timeout: float = typer.Option(
        6.0,
        "--timeout",
        min=1.0,
        max=30.0,
        help="HTTP timeout in seconds.",
        show_default=True,
    ),
    format: str = typer.Option(
        "text",
        "--format",
        help="Output format: text|json",
        show_default=True,
    ),
    out: Optional[Path] = typer.Option(None, "--out", help="Write output to a file"),
    fail_on_valid: bool = typer.Option(
        False,
        "--fail-on-valid",
        help="Exit non-zero if the secret appears valid.",
    ),
) -> None:
    if secret and from_env:
        raise typer.BadParameter("Use either a secret argument or --from-env, not both.")

    value = secret
    if from_env:
        value = os.environ.get(from_env)
        if not value:
            raise typer.BadParameter(f"Environment variable '{from_env}' is empty or missing.")

    if not value:
        raise typer.BadParameter("Provide a secret argument or --from-env VAR.")

    selected_provider = provider.strip().lower()
    allowed = SUPPORTED_PROVIDERS | {"auto"}
    if selected_provider not in allowed:
        allowed_text = ", ".join(sorted(allowed))
        raise typer.BadParameter(f"provider must be one of: {allowed_text}")

    result = verify_secret(value, provider=selected_provider, timeout=timeout)
    redacted_secret = redact(value)

    fmt = format.lower().strip()
    if fmt not in {"text", "json"}:
        raise typer.BadParameter("format must be one of: text, json")

    if fmt == "json":
        payload = result.to_dict()
        payload["secret_redacted"] = redacted_secret
        _write_text(out, json.dumps(payload, indent=2))
    else:
        _print_verify_text(result, redacted_secret)

    exit_code = 1 if (fail_on_valid and result.status == "valid") else 0
    raise typer.Exit(code=exit_code)
