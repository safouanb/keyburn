from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from urllib import error, request

SUPPORTED_PROVIDERS = {"openai", "github", "stripe"}
_USER_AGENT = "keyburn-verify/0.1"


@dataclass(frozen=True)
class VerificationResult:
    provider: str
    status: str
    confidence: int
    priority: str
    reason: str
    http_status: int | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def infer_provider(secret: str) -> str | None:
    value = secret.strip()

    if value.startswith(("sk_live_", "sk_test_", "rk_live_")):
        return "stripe"

    if value.startswith(("ghp_", "github_pat_", "gho_", "ghu_", "ghr_")):
        return "github"

    if value.startswith("sk-proj-"):
        return "openai"

    if value.startswith("sk-") and "T3BlbkFJ" in value:
        return "openai"

    return None


def _extract_message(body: str) -> str | None:
    if not body:
        return None

    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return None

    if isinstance(parsed, dict):
        error_obj = parsed.get("error")
        if isinstance(error_obj, dict):
            message = error_obj.get("message")
            if isinstance(message, str) and message.strip():
                return message.strip()

        message = parsed.get("message")
        if isinstance(message, str) and message.strip():
            return message.strip()

    return None


def _request(url: str, *, headers: dict[str, str], timeout: float) -> tuple[int, str]:
    req = request.Request(url, headers=headers, method="GET")

    try:
        with request.urlopen(req, timeout=timeout) as response:
            payload = response.read().decode("utf-8", errors="replace")
            return response.status, payload
    except error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        return exc.code, payload
    except error.URLError as exc:
        reason = str(exc.reason) if exc.reason else str(exc)
        raise RuntimeError(reason) from exc


def _valid_priority(provider: str, secret: str) -> str:
    if provider == "stripe" and secret.startswith("sk_test_"):
        return "medium"
    return "critical"


def _verify_openai(secret: str, timeout: float) -> VerificationResult:
    headers = {
        "Authorization": f"Bearer {secret}",
        "Accept": "application/json",
        "User-Agent": _USER_AGENT,
    }

    try:
        status, body = _request(
            "https://api.openai.com/v1/models", headers=headers, timeout=timeout
        )
    except RuntimeError as exc:
        return VerificationResult(
            provider="openai",
            status="error",
            confidence=25,
            priority="medium",
            reason=f"Network error while verifying OpenAI key: {exc}",
        )

    if status == 200:
        return VerificationResult(
            provider="openai",
            status="valid",
            confidence=95,
            priority=_valid_priority("openai", secret),
            reason="OpenAI accepted the key.",
            http_status=status,
        )

    if status in {401, 403}:
        msg = _extract_message(body) or "OpenAI rejected the key."
        return VerificationResult(
            provider="openai",
            status="invalid",
            confidence=95,
            priority="low",
            reason=msg,
            http_status=status,
        )

    if status == 429:
        return VerificationResult(
            provider="openai",
            status="unknown",
            confidence=60,
            priority="medium",
            reason="OpenAI rate-limited the verification request.",
            http_status=status,
        )

    return VerificationResult(
        provider="openai",
        status="unknown",
        confidence=40,
        priority="medium",
        reason=f"OpenAI returned HTTP {status}.",
        http_status=status,
    )


def _verify_github(secret: str, timeout: float) -> VerificationResult:
    headers = {
        "Authorization": f"Bearer {secret}",
        "Accept": "application/vnd.github+json",
        "User-Agent": _USER_AGENT,
    }

    try:
        status, body = _request("https://api.github.com/user", headers=headers, timeout=timeout)
    except RuntimeError as exc:
        return VerificationResult(
            provider="github",
            status="error",
            confidence=25,
            priority="medium",
            reason=f"Network error while verifying GitHub token: {exc}",
        )

    if status == 200:
        return VerificationResult(
            provider="github",
            status="valid",
            confidence=95,
            priority=_valid_priority("github", secret),
            reason="GitHub accepted the token.",
            http_status=status,
        )

    if status == 401:
        msg = _extract_message(body) or "GitHub rejected the token."
        return VerificationResult(
            provider="github",
            status="invalid",
            confidence=95,
            priority="low",
            reason=msg,
            http_status=status,
        )

    if status == 403:
        msg = _extract_message(body) or "GitHub denied access."
        return VerificationResult(
            provider="github",
            status="unknown",
            confidence=65,
            priority="medium",
            reason=msg,
            http_status=status,
        )

    return VerificationResult(
        provider="github",
        status="unknown",
        confidence=40,
        priority="medium",
        reason=f"GitHub returned HTTP {status}.",
        http_status=status,
    )


def _verify_stripe(secret: str, timeout: float) -> VerificationResult:
    headers = {
        "Authorization": f"Bearer {secret}",
        "Accept": "application/json",
        "User-Agent": _USER_AGENT,
    }

    try:
        status, body = _request(
            "https://api.stripe.com/v1/account", headers=headers, timeout=timeout
        )
    except RuntimeError as exc:
        return VerificationResult(
            provider="stripe",
            status="error",
            confidence=25,
            priority="medium",
            reason=f"Network error while verifying Stripe key: {exc}",
        )

    if status == 200:
        return VerificationResult(
            provider="stripe",
            status="valid",
            confidence=95,
            priority=_valid_priority("stripe", secret),
            reason="Stripe accepted the key.",
            http_status=status,
        )

    if status in {401, 403}:
        msg = _extract_message(body) or "Stripe rejected the key."
        return VerificationResult(
            provider="stripe",
            status="invalid",
            confidence=95,
            priority="low",
            reason=msg,
            http_status=status,
        )

    return VerificationResult(
        provider="stripe",
        status="unknown",
        confidence=40,
        priority="medium",
        reason=f"Stripe returned HTTP {status}.",
        http_status=status,
    )


def verify_secret(
    secret: str, *, provider: str = "auto", timeout: float = 6.0
) -> VerificationResult:
    value = secret.strip()
    if not value:
        return VerificationResult(
            provider="unknown",
            status="error",
            confidence=0,
            priority="low",
            reason="No secret value provided.",
        )

    selected = provider.strip().lower()
    if selected not in SUPPORTED_PROVIDERS | {"auto"}:
        return VerificationResult(
            provider=selected,
            status="error",
            confidence=0,
            priority="low",
            reason=(
                f"Unsupported provider '{selected}'. Use one of: auto, openai, github, stripe."
            ),
        )

    if selected == "auto":
        inferred = infer_provider(value)
        if inferred is None:
            return VerificationResult(
                provider="unknown",
                status="unknown",
                confidence=0,
                priority="low",
                reason="Could not infer provider from token format.",
            )
        selected = inferred

    if selected == "openai":
        return _verify_openai(value, timeout)
    if selected == "github":
        return _verify_github(value, timeout)
    if selected == "stripe":
        return _verify_stripe(value, timeout)

    return VerificationResult(
        provider=selected,
        status="error",
        confidence=0,
        priority="low",
        reason="No verifier available for selected provider.",
    )
