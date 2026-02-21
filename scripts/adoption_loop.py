#!/usr/bin/env python3
# ruff: noqa: E402
from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from keyburn.config import ScanConfig
from keyburn.scanner import scan_path, summarize

IGNORE_MARKERS = ("# keyburn:ignore", "# kb:ignore", "# noqa: keyburn")


@dataclass
class Target:
    name: str
    url: str
    branch: str = "main"


@dataclass
class RepoAdoptionResult:
    name: str
    url: str
    branch: str
    findings_total: int
    findings_high: int
    findings_medium: int
    findings_low: int
    lines_total: int
    kloc: float
    findings_per_kloc: float
    suppression_markers: int
    duration_seconds: float
    top_rules: list[dict[str, str | int]]
    status: str
    error: str | None = None


def _load_targets(path: Path) -> list[Target]:
    targets: list[Target] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"name", "url", "branch"}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            missing = sorted(required - set(reader.fieldnames or []))
            raise ValueError(f"Missing required CSV columns: {', '.join(missing)}")

        for row in reader:
            name = (row.get("name") or "").strip()
            url = (row.get("url") or "").strip()
            branch = (row.get("branch") or "main").strip()
            if name and url:
                targets.append(Target(name=name, url=url, branch=branch))

    return targets


def _clone_target(target: Target, destination: Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)

    cmd = [
        "git",
        "clone",
        "--depth",
        "1",
        "--branch",
        target.branch,
        target.url,
        str(destination),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "git clone failed"
        raise RuntimeError(message)


def _iter_text_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in {".git", "node_modules", ".venv", "venv"} for part in path.parts):
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in data:
            continue
        out.append(path)
    return out


def _repo_text_metrics(root: Path) -> tuple[int, int]:
    total_lines = 0
    suppression_markers = 0

    for path in _iter_text_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        total_lines += text.count("\n") + (1 if text and not text.endswith("\n") else 0)

        lower = text.lower()
        for marker in IGNORE_MARKERS:
            suppression_markers += lower.count(marker)

    return total_lines, suppression_markers


def _scan_target(target: Target, root: Path) -> RepoAdoptionResult:
    started = time.perf_counter()
    findings = scan_path(root, cfg=ScanConfig())
    elapsed = round(time.perf_counter() - started, 3)

    summary = summarize(findings)
    lines_total, suppression_markers = _repo_text_metrics(root)
    kloc = round(lines_total / 1000.0, 3) if lines_total > 0 else 0.0
    findings_per_kloc = round(summary["total"] / kloc, 3) if kloc > 0 else 0.0

    top_rules_counter = Counter(f.pattern_id for f in findings)
    top_rules = [{"rule": rule, "count": count} for rule, count in top_rules_counter.most_common(7)]

    return RepoAdoptionResult(
        name=target.name,
        url=target.url,
        branch=target.branch,
        findings_total=summary["total"],
        findings_high=summary["high"],
        findings_medium=summary["medium"],
        findings_low=summary["low"],
        lines_total=lines_total,
        kloc=kloc,
        findings_per_kloc=findings_per_kloc,
        suppression_markers=suppression_markers,
        duration_seconds=elapsed,
        top_rules=top_rules,
        status="ok",
    )


def _payload(results: list[RepoAdoptionResult]) -> dict[str, object]:
    ok_results = [r for r in results if r.status == "ok"]
    total_findings = sum(r.findings_total for r in ok_results)
    median_density = 0.0

    if ok_results:
        densities = sorted(r.findings_per_kloc for r in ok_results)
        mid = len(densities) // 2
        if len(densities) % 2 == 0:
            median_density = round((densities[mid - 1] + densities[mid]) / 2, 3)
        else:
            median_density = densities[mid]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "targets": len(results),
            "ok": len(ok_results),
            "errors": len(results) - len(ok_results),
            "total_findings": total_findings,
            "median_findings_per_kloc": median_density,
        },
        "repos": [asdict(r) for r in results],
    }


def _render_markdown(payload: dict[str, object]) -> str:
    summary = payload["summary"]
    repos = payload["repos"]

    lines: list[str] = []
    lines.append("# Keyburn Adoption Loop")
    lines.append("")
    lines.append(f"Generated: `{payload['generated_at']}`")
    lines.append("")
    lines.append(
        "Summary: "
        f"targets={summary['targets']}, "
        f"ok={summary['ok']}, "
        f"errors={summary['errors']}, "
        f"total_findings={summary['total_findings']}, "
        f"median_findings_per_kloc={summary['median_findings_per_kloc']}"
    )
    lines.append("")
    lines.append("| Repo | Findings | Findings/KLOC | Suppressions | Status | Time (s) |")
    lines.append("|---|---:|---:|---:|---|---:|")

    for repo in repos:
        status = str(repo["status"]).upper()
        if repo.get("error"):
            status = "ERROR"

        findings = (
            f"{repo['findings_total']} (H:{repo['findings_high']} "
            f"M:{repo['findings_medium']} L:{repo['findings_low']})"
        )
        lines.append(
            f"| [{repo['name']}]({repo['url']}) | {findings} | {repo['findings_per_kloc']} "
            f"| {repo['suppression_markers']} | {status} | {repo['duration_seconds']} |"
        )

    for repo in repos:
        if repo.get("error"):
            lines.append("")
            lines.append(f"## {repo['name']} error")
            lines.append("")
            lines.append(f"```\n{repo['error']}\n```")

    return "\n".join(lines) + "\n"


def run(args: argparse.Namespace) -> int:
    targets = _load_targets(args.targets)
    args.workspace.mkdir(parents=True, exist_ok=True)

    results: list[RepoAdoptionResult] = []
    had_errors = False

    for target in targets:
        clone_path = args.workspace / target.name

        try:
            _clone_target(target, clone_path)
            result = _scan_target(target, clone_path)
        except Exception as exc:  # pragma: no cover - network/runtime dependent
            had_errors = True
            result = RepoAdoptionResult(
                name=target.name,
                url=target.url,
                branch=target.branch,
                findings_total=0,
                findings_high=0,
                findings_medium=0,
                findings_low=0,
                lines_total=0,
                kloc=0.0,
                findings_per_kloc=0.0,
                suppression_markers=0,
                duration_seconds=0.0,
                top_rules=[],
                status="error",
                error=str(exc),
            )

        results.append(result)

    payload = _payload(results)

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)

    args.output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    args.output_md.write_text(_render_markdown(payload), encoding="utf-8")

    if args.strict and had_errors:
        return 1
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run adoption scans on external repositories and summarize noise metrics."
    )
    parser.add_argument(
        "--targets",
        type=Path,
        default=Path("adoption/targets.csv"),
        help="CSV file with adoption-loop repositories.",
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path(".adoption/repos"),
        help="Directory used for cloned repositories.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=Path("adoption/results/latest.json"),
        help="Machine-readable output path.",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=Path("adoption/results/latest.md"),
        help="Human-readable markdown output path.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero if any target fails to clone or scan.",
    )
    return parser.parse_args()


def main() -> int:
    return run(parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
