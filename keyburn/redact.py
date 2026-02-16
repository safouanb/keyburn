from __future__ import annotations


def redact(value: str, *, keep_start: int = 4, keep_end: int = 4) -> str:
    """Redact a potentially-sensitive value for display/logging."""
    if value is None:
        return ""
    if keep_start < 0 or keep_end < 0:
        raise ValueError("keep_start/keep_end must be >= 0")
    if len(value) <= keep_start + keep_end + 4:
        return "*" * len(value)
    return value[:keep_start] + ("*" * (len(value) - keep_start - keep_end)) + value[-keep_end:]


def redact_in_line(line: str, start: int, end: int) -> str:
    if start < 0 or end < start or end > len(line):
        return line
    return line[:start] + redact(line[start:end]) + line[end:]

