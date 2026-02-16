from __future__ import annotations

from pathlib import Path

from keyburn.scanner import scan_path, should_fail
from keyburn.patterns import Severity


def test_detects_github_pat(tmp_path: Path) -> None:
    p = tmp_path / "demo.txt"
    # Build the token dynamically so the repo itself doesn't contain a literal
    # PAT-looking string (the scanner is text-based and would flag it).
    token = "ghp_" + ("0123456789" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    p.write_text(f"token={token}\n", encoding="utf-8")

    findings = scan_path(tmp_path)
    assert any(f.pattern_id == "github-pat-classic" for f in findings)
    assert should_fail(findings, fail_on=Severity.high) is True


def test_respects_max_file_size(tmp_path: Path) -> None:
    p = tmp_path / "big.txt"
    p.write_bytes(b"a" * (3 * 1024 * 1024))

    findings = scan_path(tmp_path)
    assert findings == []
