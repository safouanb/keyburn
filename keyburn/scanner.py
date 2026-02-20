from __future__ import annotations

import hashlib
import os
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .config import ScanConfig
from .entropy import scan_line_entropy
from .patterns import PATTERNS, SecretPattern, Severity
from .redact import redact, redact_in_line

# Inline suppression comment — any of these on a line silence all findings for it.
_IGNORE_MARKERS = ("# keyburn:ignore", "# noqa: keyburn", "# kb:ignore")


@dataclass(frozen=True)
class Finding:
    pattern_id: str
    title: str
    severity: Severity
    path: str
    line: int
    column: int
    match_redacted: str
    fingerprint: str
    message: str
    line_text: str
    remediation: str = ""

    def to_dict(self) -> dict:
        d = {
            "pattern_id": self.pattern_id,
            "title": self.title,
            "severity": self.severity.value,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "match_redacted": self.match_redacted,
            "fingerprint": self.fingerprint,
            "message": self.message,
            "line_text": self.line_text,
        }
        if self.remediation:
            d["remediation"] = self.remediation
        return d


def _is_binary(data: bytes) -> bool:
    # NUL byte is a strong signal of a binary blob.
    return b"\x00" in data


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def _severity_at_least(a: Severity, b: Severity) -> bool:
    return a.rank >= b.rank


def _default_config() -> ScanConfig:
    return ScanConfig()


def _line_is_ignored(line: str) -> bool:
    """Return True if the line contains an inline suppression comment."""
    lower = line.lower()
    return any(marker in lower for marker in _IGNORE_MARKERS)


def _load_gitignore_patterns(root: Path) -> list[str]:
    """Load .gitignore patterns from root, returned as simple glob strings."""
    gitignore = root / ".gitignore"
    if not gitignore.exists():
        return []
    patterns: list[str] = []
    try:
        for raw in gitignore.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(line)
    except OSError:
        pass
    return patterns


def _matches_gitignore(rel_path: str, patterns: list[str]) -> bool:
    """Very lightweight gitignore matcher — handles the common cases."""
    import fnmatch

    # Normalise to forward slashes
    norm = rel_path.replace(os.sep, "/")
    name = norm.split("/")[-1]

    for pat in patterns:
        negated = pat.startswith("!")
        p = pat.lstrip("!")

        # Directory pattern (trailing slash) — match path prefix
        if p.endswith("/"):
            p = p.rstrip("/")
            if norm.startswith(p + "/") or norm == p:
                return not negated
            continue

        # Pattern with no slash — match against basename
        if "/" not in p:
            if fnmatch.fnmatch(name, p):
                return not negated
        else:
            # Pattern with slash — match against full relative path
            if fnmatch.fnmatch(norm, p) or fnmatch.fnmatch(norm, "**/" + p):
                return not negated

    return False


def _iter_files(root: Path, cfg: ScanConfig) -> Iterable[Path]:
    if root.is_file():
        yield root
        return

    gitignore_patterns = _load_gitignore_patterns(root) if cfg.respect_gitignore else []

    for dirpath, dirnames, filenames in os.walk(root):
        # In-place prune for speed.
        dirnames[:] = [d for d in dirnames if d not in cfg.exclude_dirs]

        for name in filenames:
            fpath = Path(dirpath) / name
            if gitignore_patterns:
                try:
                    rel = str(fpath.resolve().relative_to(root.resolve()))
                    if _matches_gitignore(rel, gitignore_patterns):
                        continue
                except ValueError:
                    pass

            # Check exclude_paths (fnmatch against rel path)
            if cfg.exclude_paths:
                import fnmatch

                try:
                    rel = str(fpath.resolve().relative_to(root.resolve()))
                    norm = rel.replace(os.sep, "/")
                    if any(fnmatch.fnmatch(norm, p) for p in cfg.exclude_paths):
                        continue
                except ValueError:
                    pass

            yield fpath


def scan_text(
    *,
    text: str,
    rel_path: str,
    patterns: Iterable[SecretPattern] = PATTERNS,
    cfg: ScanConfig | None = None,
    enable_entropy: bool = True,
    disabled_rules: set[str] | None = None,
) -> list[Finding]:
    cfg = cfg or _default_config()
    _disabled = disabled_rules or cfg.disable_rules
    findings: list[Finding] = []
    # Track fingerprints to avoid duplicate findings from pattern + entropy
    seen_fingerprints: set[str] = set()

    for line_no, line in enumerate(text.splitlines(), start=1):
        # Inline suppression — skip entire line
        if _line_is_ignored(line):
            continue

        # Pattern-based detection
        for pat in patterns:
            if pat.id in _disabled:
                continue

            for m in pat.regex.finditer(line):
                secret = m.group(pat.secret_group) if pat.secret_group else m.group(0)
                start = m.start(pat.secret_group) if pat.secret_group else m.start(0)
                end = m.end(pat.secret_group) if pat.secret_group else m.end(0)

                if any(rx.search(secret) for rx in cfg.allowlist_regex):
                    continue

                fingerprint = _sha256_hex(secret)
                if fingerprint in seen_fingerprints:
                    continue
                seen_fingerprints.add(fingerprint)

                findings.append(
                    Finding(
                        pattern_id=pat.id,
                        title=pat.title,
                        severity=pat.severity,
                        path=rel_path,
                        line=line_no,
                        column=start + 1,
                        match_redacted=redact(secret),
                        fingerprint=fingerprint,
                        message=(
                            f"{pat.title} detected ({pat.severity.value}). Rotate/revoke if real."
                        ),
                        line_text=redact_in_line(line, start, end),
                        remediation=pat.remediation,
                    )
                )

        # Entropy-based detection
        if enable_entropy and "entropy" not in _disabled:
            for ef in scan_line_entropy(line, line_no):
                if any(rx.search(ef.value) for rx in cfg.allowlist_regex):
                    continue

                fingerprint = _sha256_hex(ef.value)
                if fingerprint in seen_fingerprints:
                    continue
                seen_fingerprints.add(fingerprint)

                findings.append(
                    Finding(
                        pattern_id="entropy-" + ef.charset,
                        title=f"High-entropy {ef.charset} string in '{ef.var_name}'",
                        severity=Severity.medium,
                        path=rel_path,
                        line=ef.line,
                        column=ef.column,
                        match_redacted=redact(ef.value),
                        fingerprint=fingerprint,
                        message=(
                            f"High-entropy {ef.charset} string (entropy={ef.entropy}) "
                            f"assigned to '{ef.var_name}'. Could be a secret."
                        ),
                        line_text=redact_in_line(
                            line,
                            ef.column - 1,
                            ef.column - 1 + len(ef.value),
                        ),
                        remediation=(
                            f"If '{ef.var_name}' holds a real secret, move it to an "
                            "environment variable or .env file. Add .env to .gitignore."
                        ),
                    )
                )

    return findings


def scan_path(
    path: Path,
    *,
    cfg: ScanConfig | None = None,
    patterns: Iterable[SecretPattern] = PATTERNS,
    enable_entropy: bool = True,
    only_files: list[Path] | None = None,
) -> list[Finding]:
    cfg = cfg or _default_config()
    findings: list[Finding] = []

    root = path.resolve()
    base = root if root.is_dir() else root.parent

    file_iter: Iterable[Path]
    if only_files is not None:
        # --diff mode: caller provides the exact file list
        file_iter = only_files
    else:
        file_iter = _iter_files(root, cfg)

    for fpath in file_iter:
        try:
            st = fpath.stat()
        except OSError:
            continue
        if st.st_size <= 0:
            continue
        if st.st_size > cfg.max_file_size_bytes:
            continue

        try:
            data = fpath.read_bytes()
        except OSError:
            continue
        if _is_binary(data):
            continue

        try:
            rel = str(fpath.resolve().relative_to(base))
        except ValueError:
            rel = str(fpath)

        text = data.decode("utf-8", errors="replace")
        findings.extend(
            scan_text(
                text=text,
                rel_path=rel,
                patterns=patterns,
                cfg=cfg,
                enable_entropy=enable_entropy,
            )
        )

    return findings


def load_baseline(baseline_path: Path) -> set[str]:
    """Load a set of fingerprints from a baseline JSON file."""
    import json

    if not baseline_path.exists():
        return set()
    try:
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return {str(fp) for fp in data}
        if isinstance(data, dict) and "fingerprints" in data:
            return {str(fp) for fp in data["fingerprints"]}
    except (OSError, ValueError):
        pass
    return set()


def save_baseline(findings: Iterable[Finding], baseline_path: Path) -> None:
    """Write current finding fingerprints as a baseline JSON file."""
    import json

    fps = sorted({f.fingerprint for f in findings})
    baseline_path.write_text(
        json.dumps({"fingerprints": fps}, indent=2),
        encoding="utf-8",
    )


def filter_baseline(findings: list[Finding], baseline: set[str]) -> list[Finding]:
    """Remove findings whose fingerprint appears in the baseline."""
    return [f for f in findings if f.fingerprint not in baseline]


def summarize(findings: Iterable[Finding]) -> dict:
    out = {"total": 0, "low": 0, "medium": 0, "high": 0}
    for f in findings:
        out["total"] += 1
        out[f.severity.value] += 1
    return out


def should_fail(findings: Iterable[Finding], *, fail_on: Severity) -> bool:
    return any(_severity_at_least(f.severity, fail_on) for f in findings)
