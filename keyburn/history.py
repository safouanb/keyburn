from __future__ import annotations

import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .config import ScanConfig
from .patterns import PATTERNS, SecretPattern
from .scanner import Finding, scan_text


@dataclass(frozen=True)
class CommitInfo:
    sha: str
    author: str
    date: str
    subject: str


def _git(*args: str, cwd: Path) -> str:
    """Run a git command and return stdout. Returns empty string on failure."""
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


def _list_commits(repo: Path, max_count: int | None) -> list[CommitInfo]:
    """Return commits from newest to oldest."""
    args = ["log", "--format=%H\t%an\t%ad\t%s", "--date=short"]
    if max_count is not None:
        args += [f"-{max_count}"]

    out = _git(*args, cwd=repo)
    commits: list[CommitInfo] = []
    for line in out.splitlines():
        parts = line.split("\t", 3)
        if len(parts) < 4:
            continue
        commits.append(CommitInfo(sha=parts[0], author=parts[1], date=parts[2], subject=parts[3]))
    return commits


def _get_commit_diff(repo: Path, sha: str) -> str:
    """Return the unified diff introduced by this commit (added lines only context)."""
    return _git("show", "--unified=0", sha, cwd=repo)


def parse_diff_hunks(diff: str) -> list[tuple[str, int, str]]:
    """
    Parse a unified diff and return (filepath, line_no, added_line) tuples
    for every line that was ADDED by the commit (lines starting with '+',
    excluding the +++ header lines).
    """
    results: list[tuple[str, int, str]] = []
    current_file = ""
    current_line = 0

    for line in diff.splitlines():
        # New file in diff
        if line.startswith("+++ b/"):
            current_file = line[6:]
            current_line = 0
            continue
        if line.startswith("---") or line.startswith("diff ") or line.startswith("index "):
            continue

        # Hunk header: @@ -old_start,old_count +new_start,new_count @@
        if line.startswith("@@"):
            # Extract new-file starting line number
            try:
                new_part = line.split("+")[1].split("@@")[0].strip()
                current_line = int(new_part.split(",")[0]) - 1
            except (IndexError, ValueError):
                current_line = 0
            continue

        if line.startswith("+"):
            current_line += 1
            results.append((current_file, current_line, line[1:]))
        elif not line.startswith("-"):
            current_line += 1

    return results


def _parse_diff_hunks(diff: str) -> list[tuple[str, int, str]]:
    """Backward-compatible alias used by older tests/imports."""
    return parse_diff_hunks(diff)


@dataclass(frozen=True)
class HistoryFinding:
    """A finding in git history, with the commit it was introduced in."""

    finding: Finding
    commit: CommitInfo


def scan_history(
    repo: Path,
    *,
    max_commits: int | None = 50,
    cfg: ScanConfig | None = None,
    patterns: Iterable[SecretPattern] = PATTERNS,
    enable_entropy: bool = True,
) -> list[HistoryFinding]:
    """
    Scan git history for secrets introduced in past commits.

    Only examines lines ADDED by each commit, so secrets that were added
    then deleted are still caught. Deduplicates across commits by fingerprint
    so the same secret isn't reported once per commit.

    Args:
        repo: Path to the git repository root.
        max_commits: How many commits to scan (None = full history).
        cfg: Scanner config (allowlists, etc.).
        patterns: Detection patterns to use.
        enable_entropy: Whether to run entropy detection.
    """
    from .config import ScanConfig as _SC

    cfg = cfg or _SC()
    commits = _list_commits(repo, max_commits)
    seen_fingerprints: set[str] = set()
    results: list[HistoryFinding] = []

    for commit in commits:
        diff = _get_commit_diff(repo, commit.sha)
        hunks = parse_diff_hunks(diff)

        # Group added lines by file path, preserving line numbers
        files: dict[str, list[tuple[int, str]]] = {}
        for fpath, lineno, content in hunks:
            files.setdefault(fpath, []).append((lineno, content))

        for fpath, lines in files.items():
            # Skip excluded dirs/paths based on config
            if any(excl in fpath for excl in cfg.exclude_dirs):
                continue

            # Reconstruct a fake "file" text where each line is at its correct
            # number by padding with empty lines. scan_text uses enumerate(splitlines).
            if not lines:
                continue
            max_line = max(ln for ln, _ in lines)
            line_map: dict[int, str] = {ln: content for ln, content in lines}
            text_lines = [line_map.get(i, "") for i in range(1, max_line + 1)]
            text = "\n".join(text_lines)

            findings = scan_text(
                text=text,
                rel_path=fpath,
                patterns=patterns,
                cfg=cfg,
                enable_entropy=enable_entropy,
            )

            for f in findings:
                if f.fingerprint in seen_fingerprints:
                    continue
                seen_fingerprints.add(f.fingerprint)
                results.append(HistoryFinding(finding=f, commit=commit))

    return results
