from __future__ import annotations

from dataclasses import dataclass

from .patterns import Severity


@dataclass(frozen=True)
class IncidentPlaybook:
    id: str
    title: str
    provider: str
    steps: tuple[str, ...]
    rotation_stub: str = ""

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "id": self.id,
            "title": self.title,
            "provider": self.provider,
            "steps": list(self.steps),
        }
        if self.rotation_stub:
            out["rotation_stub"] = self.rotation_stub
        return out


def _rotation_stub(provider: str) -> str:
    if provider in {"aws", "github", "stripe"}:
        return f"keyburn rotate --provider {provider} --resource <resource-id>"
    return ""


def _provider_steps(provider: str) -> tuple[str, ...]:
    if provider == "aws":
        return (
            "Disable the leaked access key immediately and create a replacement key.",
            "Update all IAM-backed secrets in CI/CD and secret stores.",
            "Audit CloudTrail for suspicious API calls tied to the leaked key.",
        )
    if provider == "github":
        return (
            "Revoke the leaked token in GitHub settings (or app settings) immediately.",
            "Replace repo/org Actions secrets that referenced the leaked token.",
            "Review audit logs for token usage from unfamiliar IPs or agents.",
        )
    if provider == "stripe":
        return (
            "Roll the leaked key in Stripe Dashboard > Developers > API keys.",
            "Update backend secrets and redeploy all services using Stripe credentials.",
            "Monitor recent charges/refunds/events for suspicious activity.",
        )
    if provider in {"openai", "anthropic", "groq"}:
        return (
            "Revoke and regenerate the leaked AI provider key in the provider dashboard.",
            "Update server-side environment variables and redeploy dependent services.",
            "Review usage/billing spikes around the leak window.",
        )
    return (
        "Revoke or rotate the leaked credential at the provider as soon as possible.",
        "Replace every downstream secret reference and redeploy affected services.",
        "Review access logs for suspicious activity since the first exposure.",
    )


def _provider_title(provider: str) -> str:
    if provider == "aws":
        return "AWS Credential Leak Response"
    if provider == "github":
        return "GitHub Token Leak Response"
    if provider == "stripe":
        return "Stripe Key Leak Response"
    if provider in {"openai", "anthropic", "groq"}:
        return f"{provider.title()} API Key Leak Response"
    return "Credential Leak Response"


def build_incident_playbook(
    provider: str, *, severity: Severity, pattern_id: str, risk_score: int
) -> IncidentPlaybook:
    normalized = (provider or "unknown").strip().lower() or "unknown"
    steps = list(_provider_steps(normalized))

    if severity == Severity.high:
        steps.insert(0, "Pause risky deploys until key rotation is complete.")
    if risk_score >= 90:
        steps.insert(
            0,
            "Treat as active incident: assign owner, open incident channel, and track ETA.",
        )
    if "entropy" in pattern_id:
        steps.append("Confirm whether this value is a real secret before suppressing.")

    playbook_id = f"{normalized}-key-leak" if normalized != "unknown" else "generic-key-leak"
    return IncidentPlaybook(
        id=playbook_id,
        title=_provider_title(normalized),
        provider=normalized,
        steps=tuple(steps),
        rotation_stub=_rotation_stub(normalized),
    )
