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


def _iter_files(root: Path, cfg: ScanConfig) -> Iterable[Path]:
    if root.is_file():
        yield root
        return

    for dirpath, dirnames, filenames in os.walk(root):
        # In-place prune for speed.
        dirnames[:] = [d for d in dirnames if d not in cfg.exclude_dirs]
        for name in filenames:
            yield Path(dirpath) / name


def scan_text(
    *,
    text: str,
    rel_path: str,
    patterns: Iterable[SecretPattern] = PATTERNS,
    cfg: ScanConfig | None = None,
    enable_entropy: bool = True,
) -> list[Finding]:
    cfg = cfg or _default_config()
    findings: list[Finding] = []
    # Track fingerprints to avoid duplicate findings from pattern + entropy
    seen_fingerprints: set[str] = set()

    for line_no, line in enumerate(text.splitlines(), start=1):
        # Pattern-based detection
        for pat in patterns:
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
        if enable_entropy:
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
) -> list[Finding]:
    cfg = cfg or _default_config()
    findings: list[Finding] = []

    root = path.resolve()
    base = root if root.is_dir() else root.parent

    for fpath in _iter_files(root, cfg):
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

        rel = str(fpath.resolve().relative_to(base))
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


def summarize(findings: Iterable[Finding]) -> dict:
    out = {"total": 0, "low": 0, "medium": 0, "high": 0}
    for f in findings:
        out["total"] += 1
        out[f.severity.value] += 1
    return out


def should_fail(findings: Iterable[Finding], *, fail_on: Severity) -> bool:
    return any(_severity_at_least(f.severity, fail_on) for f in findings)
