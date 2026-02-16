from __future__ import annotations

import math
import re
from dataclasses import dataclass

# Character sets for entropy calculation
_BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_HEX_CHARS = set("0123456789abcdefABCDEF")

# Minimum token length to consider for entropy analysis
MIN_TOKEN_LENGTH = 12

# Entropy thresholds — tuned to reduce false positives
BASE64_ENTROPY_THRESHOLD = 4.2
HEX_ENTROPY_THRESHOLD = 3.5

# Keywords that signal a variable is meant to hold a secret
SECRET_VAR_KEYWORDS = frozenset(
    {
        "key",
        "secret",
        "token",
        "password",
        "passwd",
        "credential",
        "auth",
        "api_key",
        "apikey",
        "api-key",
        "access_token",
        "private",
        "encryption",
    }
)

# Common false positives — hashes, UUIDs, module names, etc.
_FALSE_POSITIVE_RX = re.compile(
    r"^("
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"  # UUID
    r"|sha[0-9]+-[A-Za-z0-9+/=]+"  # integrity hashes
    r"|[a-f0-9]{64}"  # SHA-256 (standalone hash, not a secret)
    r"|v\d+\.\d+\.\d+"  # semver
    r"|https?://.*"  # URLs
    r")$",
    re.IGNORECASE,
)

# Assignment pattern: VAR_NAME = "value" or VAR_NAME: "value"
_ASSIGNMENT_RX = re.compile(
    r"""(?:^|[;\s])"""
    r"""([A-Za-z_][A-Za-z0-9_.-]*)"""  # variable name
    r"""\s*[:=]\s*"""  # assignment operator
    r"""['\"]([^'"]{12,})['\"]""",  # quoted value
)


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0

    length = len(data)
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _charset_ratio(data: str, charset: set[str]) -> float:
    """Fraction of characters in data that belong to charset."""
    if not data:
        return 0.0
    return sum(1 for c in data if c in charset) / len(data)


def _has_secret_keyword(var_name: str) -> bool:
    """Check if a variable name contains a secret-related keyword."""
    lower = var_name.lower()
    return any(kw in lower for kw in SECRET_VAR_KEYWORDS)


@dataclass(frozen=True)
class EntropyFinding:
    var_name: str
    value: str
    entropy: float
    line: int
    column: int
    charset: str  # "base64" or "hex"


def scan_line_entropy(
    line: str,
    line_no: int,
    *,
    min_length: int = MIN_TOKEN_LENGTH,
    base64_threshold: float = BASE64_ENTROPY_THRESHOLD,
    hex_threshold: float = HEX_ENTROPY_THRESHOLD,
) -> list[EntropyFinding]:
    """Scan a single line for high-entropy strings in assignments.

    Only flags values where the variable name suggests it holds a secret
    (e.g. API_KEY, SECRET, TOKEN) AND the value has high entropy.
    This two-signal approach reduces false positives significantly.
    """
    findings: list[EntropyFinding] = []

    for m in _ASSIGNMENT_RX.finditer(line):
        var_name = m.group(1)
        value = m.group(2)

        if len(value) < min_length:
            continue

        # Only flag if variable name looks secret-related
        if not _has_secret_keyword(var_name):
            continue

        # Skip common false positives
        if _FALSE_POSITIVE_RX.match(value):
            continue

        # Calculate entropy based on character set
        b64_ratio = _charset_ratio(value, _BASE64_CHARS)
        hex_ratio = _charset_ratio(value, _HEX_CHARS)

        entropy = shannon_entropy(value)
        charset: str | None = None

        if hex_ratio > 0.95 and entropy >= hex_threshold:
            charset = "hex"
        elif b64_ratio > 0.85 and entropy >= base64_threshold:
            charset = "base64"

        if charset is not None:
            findings.append(
                EntropyFinding(
                    var_name=var_name,
                    value=value,
                    entropy=round(entropy, 2),
                    line=line_no,
                    column=m.start(2) + 1,
                    charset=charset,
                )
            )

    return findings
