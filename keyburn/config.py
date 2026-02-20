from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
}


@dataclass
class ScanConfig:
    max_file_size_bytes: int = 2 * 1024 * 1024
    exclude_dirs: set[str] = field(default_factory=lambda: set(DEFAULT_EXCLUDE_DIRS))
    exclude_globs: list[str] = field(default_factory=list)
    # Glob patterns matched against relative file paths (e.g. "tests/fixtures/**")
    exclude_paths: list[str] = field(default_factory=list)
    allowlist_regex: list[re.Pattern[str]] = field(default_factory=list)
    # Rule IDs to skip entirely (also accepts "entropy" to skip all entropy checks)
    disable_rules: set[str] = field(default_factory=set)
    # Whether to skip files listed in .gitignore
    respect_gitignore: bool = True


def _compile_allowlist(patterns: Iterable[str]) -> list[re.Pattern[str]]:
    compiled: list[re.Pattern[str]] = []
    for p in patterns:
        if not p:
            continue
        compiled.append(re.compile(p))
    return compiled


def load_config(config_path: Path | None) -> ScanConfig:
    """Load keyburn config. Missing config is not an error."""
    if config_path is None:
        config_path = Path("keyburn.toml")
    if not config_path.exists():
        return ScanConfig()

    raw = config_path.read_text(encoding="utf-8")

    # Avoid importing TOML parsers at module import time so the scanner can run
    # in minimal environments. In normal installs, `tomli` is pulled in on
    # Python < 3.11 via extras/deps.
    try:  # pragma: no cover
        import tomllib  # py311+

        data = tomllib.loads(raw)
    except ModuleNotFoundError:  # pragma: no cover
        try:
            import tomli

            data = tomli.loads(raw)
        except ModuleNotFoundError:
            # No TOML parser available; fall back to defaults.
            return ScanConfig()
    cfg = ScanConfig()

    scan = data.get("scan", {})
    if isinstance(scan, dict):
        mfs = scan.get("max_file_size_bytes")
        if isinstance(mfs, int) and mfs > 0:
            cfg.max_file_size_bytes = mfs

        ex_dirs = scan.get("exclude_dirs")
        if isinstance(ex_dirs, list):
            cfg.exclude_dirs.update({str(x) for x in ex_dirs if x})

        ex_globs = scan.get("exclude_globs")
        if isinstance(ex_globs, list):
            cfg.exclude_globs = [str(x) for x in ex_globs if x]

        ex_paths = scan.get("exclude_paths")
        if isinstance(ex_paths, list):
            cfg.exclude_paths = [str(x) for x in ex_paths if x]

        disable = scan.get("disable_rules")
        if isinstance(disable, list):
            cfg.disable_rules = {str(x) for x in disable if x}

        respect_gi = scan.get("respect_gitignore")
        if isinstance(respect_gi, bool):
            cfg.respect_gitignore = respect_gi

    allow = data.get("allowlist", {})
    if isinstance(allow, dict):
        rx = allow.get("regex")
        if isinstance(rx, list):
            cfg.allowlist_regex = _compile_allowlist([str(x) for x in rx if x])

    return cfg
