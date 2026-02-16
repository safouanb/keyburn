from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Pattern


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"

    @property
    def rank(self) -> int:
        return {"low": 1, "medium": 2, "high": 3}[self.value]


@dataclass(frozen=True)
class SecretPattern:
    id: str
    title: str
    description: str
    severity: Severity
    category: str
    regex: Pattern[str]
    secret_group: int = 0


def _re(pattern: str, *, flags: int = re.IGNORECASE) -> Pattern[str]:
    return re.compile(pattern, flags)


PATTERNS: list[SecretPattern] = [
    SecretPattern(
        id="aws-access-key-id",
        title="AWS Access Key ID",
        description="Looks like an AWS access key id (AKIA/ASIA...).",
        severity=Severity.high,
        category="aws",
        regex=_re(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", flags=0),
    ),
    SecretPattern(
        id="aws-secret-access-key",
        title="AWS Secret Access Key",
        description="Looks like an AWS secret access key assignment.",
        severity=Severity.high,
        category="aws",
        regex=_re(r"\baws_secret_access_key\b\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        secret_group=1,
    ),
    SecretPattern(
        id="github-pat-classic",
        title="GitHub PAT (classic)",
        description="Looks like a GitHub personal access token (classic).",
        severity=Severity.high,
        category="github",
        regex=_re(r"\bghp_[A-Za-z0-9]{36}\b", flags=0),
    ),
    SecretPattern(
        id="github-pat-fine-grained",
        title="GitHub PAT (fine-grained)",
        description="Looks like a GitHub fine-grained personal access token.",
        severity=Severity.high,
        category="github",
        regex=_re(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", flags=0),
    ),
    SecretPattern(
        id="slack-token",
        title="Slack token",
        description="Looks like a Slack token (xoxb/xoxp/xoxa/xoxr).",
        severity=Severity.high,
        category="slack",
        regex=_re(r"\bxox[abopr]-[0-9A-Za-z-]{10,}\b", flags=0),
    ),
    SecretPattern(
        id="stripe-secret-live",
        title="Stripe Secret Key (live)",
        description="Looks like a Stripe live secret key.",
        severity=Severity.high,
        category="stripe",
        regex=_re(r"\bsk_live_[0-9a-zA-Z]{20,}\b", flags=0),
    ),
    SecretPattern(
        id="stripe-secret-test",
        title="Stripe Secret Key (test)",
        description="Looks like a Stripe test secret key.",
        severity=Severity.medium,
        category="stripe",
        regex=_re(r"\bsk_test_[0-9a-zA-Z]{20,}\b", flags=0),
    ),
    SecretPattern(
        id="google-api-key",
        title="Google API Key",
        description="Looks like a Google API key (AIza...).",
        severity=Severity.high,
        category="gcp",
        regex=_re(r"\bAIza[0-9A-Za-z\-_]{35}\b", flags=0),
    ),
    SecretPattern(
        id="openai-api-key-assignment",
        title="OpenAI API key assignment",
        description="Looks like an OpenAI API key in a typical env/setting assignment.",
        severity=Severity.high,
        category="openai",
        regex=_re(r"\b(openai[_-]?api[_-]?key|OPENAI_API_KEY)\b\s*[:=]\s*['\"]?(sk-[A-Za-z0-9]{20,})['\"]?"),
        secret_group=2,
    ),
    SecretPattern(
        id="private-key-block",
        title="Private key block",
        description="Looks like a PEM private key block header.",
        severity=Severity.high,
        category="crypto",
        regex=_re(r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----", flags=0),
    ),
]

