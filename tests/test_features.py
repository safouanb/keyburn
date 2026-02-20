from __future__ import annotations

import json
from pathlib import Path

import pytest

from keyburn.config import ScanConfig, load_config
from keyburn.scanner import (
    filter_baseline,
    load_baseline,
    save_baseline,
    scan_path,
    scan_text,
)

# ---------------------------------------------------------------------------
# Inline ignore comments
# ---------------------------------------------------------------------------


def test_inline_ignore_suppresses_finding() -> None:
    key = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    text = f"STRIPE_KEY={key}  # keyburn:ignore"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert len(findings) == 0


def test_kb_ignore_alias_works() -> None:
    key = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    text = f"STRIPE_KEY={key}  # kb:ignore"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert len(findings) == 0


def test_noqa_keyburn_alias_works() -> None:
    key = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    text = f"STRIPE_KEY={key}  # noqa: keyburn"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert len(findings) == 0


def test_ignore_only_suppresses_that_line() -> None:
    key = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    other_key = "sk_live_" + "z9y8x7w6v5u4t3s2r1q0p9o8"
    text = f"KEY1={key}  # keyburn:ignore\nKEY2={other_key}"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    # Only the second line should fire
    assert len(findings) == 1
    assert findings[0].line == 2


def test_ignore_case_insensitive() -> None:
    key = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    text = f"STRIPE_KEY={key}  # KEYBURN:IGNORE"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert len(findings) == 0


# ---------------------------------------------------------------------------
# Disable rules via config
# ---------------------------------------------------------------------------


def test_disable_rule_suppresses_pattern() -> None:
    cfg = ScanConfig(disable_rules={"stripe-secret-live"})
    key = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    text = f"STRIPE_KEY={key}"
    findings = scan_text(text=text, rel_path="test.py", cfg=cfg, enable_entropy=False)
    assert not any(f.pattern_id == "stripe-secret-live" for f in findings)


def test_disable_entropy_suppresses_entropy_findings() -> None:
    cfg = ScanConfig(disable_rules={"entropy"})
    value = "aB3dE5gH7jK9mN1pQ3sT5uW7yZ0bC2eF"
    text = f'my_auth_token = "{value}"'
    findings = scan_text(text=text, rel_path="config.py", cfg=cfg, enable_entropy=True)
    entropy_findings = [f for f in findings if f.pattern_id.startswith("entropy-")]
    assert len(entropy_findings) == 0


def test_disable_rules_from_toml(tmp_path: Path) -> None:
    toml = tmp_path / "keyburn.toml"
    toml.write_text(
        '[scan]\ndisable_rules = ["stripe-secret-live", "entropy"]\n',
        encoding="utf-8",
    )
    cfg = load_config(toml)
    assert "stripe-secret-live" in cfg.disable_rules
    assert "entropy" in cfg.disable_rules


# ---------------------------------------------------------------------------
# Exclude paths
# ---------------------------------------------------------------------------


def test_exclude_paths_skips_matched_files(tmp_path: Path) -> None:
    fixture = tmp_path / "tests" / "fixtures" / "sample.py"
    fixture.parent.mkdir(parents=True)
    key = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    fixture.write_text(f"KEY={key}\n", encoding="utf-8")

    cfg = ScanConfig(exclude_paths=["tests/fixtures/**"])
    findings = scan_path(tmp_path, cfg=cfg)
    assert len(findings) == 0


def test_exclude_paths_from_toml(tmp_path: Path) -> None:
    toml = tmp_path / "keyburn.toml"
    toml.write_text(
        '[scan]\nexclude_paths = ["tests/fixtures/**", "docs/**"]\n',
        encoding="utf-8",
    )
    cfg = load_config(toml)
    assert "tests/fixtures/**" in cfg.exclude_paths
    assert "docs/**" in cfg.exclude_paths


# ---------------------------------------------------------------------------
# .gitignore awareness
# ---------------------------------------------------------------------------


def test_gitignore_skips_ignored_files(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("secrets.env\n*.secret\n", encoding="utf-8")

    secret_file = tmp_path / "secrets.env"
    key = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    secret_file.write_text(f"KEY={key}\n", encoding="utf-8")

    cfg = ScanConfig(respect_gitignore=True)
    findings = scan_path(tmp_path, cfg=cfg)
    assert len(findings) == 0


def test_gitignore_disabled_scans_ignored_files(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("secrets.env\n", encoding="utf-8")

    secret_file = tmp_path / "secrets.env"
    key = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    secret_file.write_text(f"KEY={key}\n", encoding="utf-8")

    cfg = ScanConfig(respect_gitignore=False)
    findings = scan_path(tmp_path, cfg=cfg)
    assert len(findings) >= 1


def test_gitignore_wildcard_pattern(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("*.secret\n", encoding="utf-8")

    f = tmp_path / "prod.secret"
    key = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    f.write_text(f"KEY={key}\n", encoding="utf-8")

    cfg = ScanConfig(respect_gitignore=True)
    findings = scan_path(tmp_path, cfg=cfg)
    assert len(findings) == 0


def test_gitignore_does_not_skip_unignored_files(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("secrets.env\n", encoding="utf-8")

    real_file = tmp_path / "app.py"
    key = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    real_file.write_text(f"KEY={key}\n", encoding="utf-8")

    cfg = ScanConfig(respect_gitignore=True)
    findings = scan_path(tmp_path, cfg=cfg)
    assert len(findings) >= 1


# ---------------------------------------------------------------------------
# Baseline — save / load / filter
# ---------------------------------------------------------------------------


def test_save_and_load_baseline(tmp_path: Path) -> None:
    key = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    text = f"KEY={key}"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert findings

    baseline_file = tmp_path / "baseline.json"
    save_baseline(findings, baseline_file)

    loaded = load_baseline(baseline_file)
    assert findings[0].fingerprint in loaded


def test_filter_baseline_removes_known_findings() -> None:
    key = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    text = f"KEY={key}"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert findings

    known = {f.fingerprint for f in findings}
    filtered = filter_baseline(findings, known)
    assert len(filtered) == 0


def test_filter_baseline_keeps_new_findings() -> None:
    key1 = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    key2 = "sk_live_" + "z9y8x7w6v5u4t3s2r1q0p9o8"
    text1 = f"KEY={key1}"
    text2 = f"KEY={key2}"
    findings1 = scan_text(text=text1, rel_path="test.py", enable_entropy=False)
    findings2 = scan_text(text=text2, rel_path="test.py", enable_entropy=False)

    known = {f.fingerprint for f in findings1}
    all_findings = findings1 + findings2
    filtered = filter_baseline(all_findings, known)

    # findings1 suppressed, findings2 remain
    assert len(filtered) == len(findings2)
    assert all(f.fingerprint not in known for f in filtered)


def test_load_baseline_missing_file(tmp_path: Path) -> None:
    result = load_baseline(tmp_path / "nonexistent.json")
    assert result == set()


def test_baseline_json_structure(tmp_path: Path) -> None:
    key = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    text = f"KEY={key}"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)

    baseline_file = tmp_path / "baseline.json"
    save_baseline(findings, baseline_file)

    data = json.loads(baseline_file.read_text())
    assert "fingerprints" in data
    assert isinstance(data["fingerprints"], list)
    assert len(data["fingerprints"]) >= 1


# ---------------------------------------------------------------------------
# Only-files (diff mode plumbing)
# ---------------------------------------------------------------------------


def test_only_files_limits_scan(tmp_path: Path) -> None:
    key = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"

    f1 = tmp_path / "a.py"
    f2 = tmp_path / "b.py"
    f1.write_text(f"KEY={key}\n")
    f2.write_text(f"KEY={key}\n")

    # Scan only f1
    findings = scan_path(tmp_path, only_files=[f1])
    paths = {f.path for f in findings}
    assert all("a.py" in p for p in paths)
    assert not any("b.py" in p for p in paths)


def test_only_files_empty_list_returns_no_findings(tmp_path: Path) -> None:
    key = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    f = tmp_path / "a.py"
    f.write_text(f"KEY={key}\n")

    findings = scan_path(tmp_path, only_files=[])
    assert findings == []


# ---------------------------------------------------------------------------
# Config: respect_gitignore toml setting
# ---------------------------------------------------------------------------


def test_respect_gitignore_false_from_toml(tmp_path: Path) -> None:
    toml = tmp_path / "keyburn.toml"
    toml.write_text("[scan]\nrespect_gitignore = false\n", encoding="utf-8")
    cfg = load_config(toml)
    assert cfg.respect_gitignore is False


def test_respect_gitignore_true_by_default() -> None:
    cfg = ScanConfig()
    assert cfg.respect_gitignore is True


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_ignore_comment_on_clean_line_is_harmless() -> None:
    text = "x = 1  # keyburn:ignore"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert findings == []


@pytest.mark.parametrize(
    "marker",
    ["# keyburn:ignore", "# kb:ignore", "# noqa: keyburn"],
)
def test_all_ignore_markers(marker: str) -> None:
    key = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    text = f"KEY={key}  {marker}"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert len(findings) == 0
