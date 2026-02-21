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


@dataclass
class RepoTarget:
    name: str
    url: str
    expected_max_findings: int = 0


@dataclass
class RepoResult:
    name: str
    url: str
    expected_max_findings: int
    findings_total: int
    findings_high: int
    findings_medium: int
    findings_low: int
    status: str
    duration_seconds: float
    top_rules: list[dict[str, str | int]]
    samples: list[dict[str, str]]
    error: str | None = None


def _load_targets(path: Path) -> list[RepoTarget]:
    targets: list[RepoTarget] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"name", "url", "expected_max_findings"}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            missing = sorted(required - set(reader.fieldnames or []))
            raise ValueError(f"Missing required CSV columns: {', '.join(missing)}")

        for row in reader:
            name = (row.get("name") or "").strip()
            url = (row.get("url") or "").strip()
            raw_expected = (row.get("expected_max_findings") or "0").strip()

            if not name or not url:
                continue

            try:
                expected = int(raw_expected)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid expected_max_findings '{raw_expected}' for target '{name}'"
                ) from exc

            targets.append(RepoTarget(name=name, url=url, expected_max_findings=max(expected, 0)))

    return targets


def _clone_target(target: RepoTarget, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)

    cmd = ["git", "clone", "--depth", "1", target.url, str(dest)]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "git clone failed"
        raise RuntimeError(message)


def _scan_target(target: RepoTarget, path: Path) -> RepoResult:
    started = time.perf_counter()
    findings = scan_path(path, cfg=ScanConfig())
    elapsed = round(time.perf_counter() - started, 3)

    summary = summarize(findings)
    top_rules_counter = Counter(f.pattern_id for f in findings)
    top_rules = [
        {"rule": rule_id, "count": count} for rule_id, count in top_rules_counter.most_common(5)
    ]

    samples = [
        {
            "severity": finding.severity.value,
            "rule": finding.pattern_id,
            "location": f"{finding.path}:{finding.line}",
        }
        for finding in findings[:5]
    ]

    status = "pass" if summary["total"] <= target.expected_max_findings else "review"

    return RepoResult(
        name=target.name,
        url=target.url,
        expected_max_findings=target.expected_max_findings,
        findings_total=summary["total"],
        findings_high=summary["high"],
        findings_medium=summary["medium"],
        findings_low=summary["low"],
        status=status,
        duration_seconds=elapsed,
        top_rules=top_rules,
        samples=samples,
    )


def _render_markdown(payload: dict) -> str:
    lines: list[str] = []
    summary = payload["summary"]

    lines.append("# Keyburn Precision Benchmark")
    lines.append("")
    lines.append(f"Generated: `{payload['generated_at']}`")
    lines.append("")
    lines.append(
        "Summary: "
        f"targets={summary['targets']}, "
        f"within_threshold={summary['within_threshold']}, "
        f"needs_review={summary['needs_review']}, "
        f"errors={summary['errors']}, "
        f"total_findings={summary['total_findings']}"
    )
    lines.append("")
    lines.append("| Repo | Findings | Expected max | Status | Runtime (s) |")
    lines.append("|---|---:|---:|---|---:|")

    for repo in payload["repos"]:
        status = "ERROR" if repo.get("error") else repo["status"].upper()
        lines.append(
            f"| [{repo['name']}]({repo['url']}) | {repo['findings_total']} "
            f"(H:{repo['findings_high']} M:{repo['findings_medium']} L:{repo['findings_low']}) "
            f"| {repo['expected_max_findings']} | {status} | {repo['duration_seconds']:.3f} |"
        )

    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- PASS means findings stayed at or below the configured threshold for that repo.")
    lines.append(
        "- REVIEW means findings exceeded the threshold and should be triaged for false positives."
    )
    lines.append(
        "- This benchmark tracks precision/noise trends over time; it does not measure full recall."
    )

    for repo in payload["repos"]:
        if repo.get("error"):
            lines.append("")
            lines.append(f"### {repo['name']} error")
            lines.append("")
            lines.append(f"```\n{repo['error']}\n```")
            continue

        if not repo.get("samples"):
            continue

        lines.append("")
        lines.append(f"### {repo['name']} sample findings")
        lines.append("")
        for sample in repo["samples"]:
            lines.append(
                f"- `{sample['severity'].upper()}` `{sample['rule']}` at `{sample['location']}`"
            )

    lines.append("")
    return "\n".join(lines)


def _build_payload(results: list[RepoResult]) -> dict:
    total_findings = sum(r.findings_total for r in results)
    errors = sum(1 for r in results if r.error)
    within_threshold = sum(1 for r in results if not r.error and r.status == "pass")
    needs_review = sum(1 for r in results if not r.error and r.status == "review")

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "targets": len(results),
            "within_threshold": within_threshold,
            "needs_review": needs_review,
            "errors": errors,
            "total_findings": total_findings,
        },
        "repos": [asdict(r) for r in results],
    }


def run(args: argparse.Namespace) -> int:
    targets = _load_targets(args.repos_file)
    args.workspace.mkdir(parents=True, exist_ok=True)

    results: list[RepoResult] = []
    had_errors = False

    for target in targets:
        dest = args.workspace / target.name

        try:
            _clone_target(target, dest)
            result = _scan_target(target, dest)
        except Exception as exc:  # pragma: no cover - network/git/runtime dependent
            had_errors = True
            result = RepoResult(
                name=target.name,
                url=target.url,
                expected_max_findings=target.expected_max_findings,
                findings_total=0,
                findings_high=0,
                findings_medium=0,
                findings_low=0,
                status="error",
                duration_seconds=0.0,
                top_rules=[],
                samples=[],
                error=str(exc),
            )

        results.append(result)

    payload = _build_payload(results)

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    args.output_md.write_text(_render_markdown(payload), encoding="utf-8")

    if args.strict and had_errors:
        return 1
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run precision/noise benchmarks on real OSS repos and write JSON + Markdown reports."
        )
    )
    parser.add_argument(
        "--repos-file",
        type=Path,
        default=Path("benchmarks/repos.csv"),
        help="CSV file with benchmark targets.",
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path(".benchmarks/repos"),
        help="Where repositories are cloned for scanning.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=Path("benchmarks/results/latest.json"),
        help="Output path for machine-readable benchmark results.",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=Path("benchmarks/results/latest.md"),
        help="Output path for human-readable benchmark results.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when any repository cannot be cloned/scanned.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
