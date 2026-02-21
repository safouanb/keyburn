from __future__ import annotations

from dataclasses import dataclass

SUPPORTED_ROTATE_PROVIDERS = {"aws", "github", "stripe"}


@dataclass(frozen=True)
class RotationPlan:
    provider: str
    resource: str
    summary: str
    commands: tuple[str, ...]
    checks: tuple[str, ...]
    notes: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "resource": self.resource,
            "summary": self.summary,
            "commands": list(self.commands),
            "checks": list(self.checks),
            "notes": list(self.notes),
        }


def build_rotation_plan(provider: str, *, resource: str | None = None) -> RotationPlan:
    selected = provider.strip().lower()
    if selected not in SUPPORTED_ROTATE_PROVIDERS:
        allowed = ", ".join(sorted(SUPPORTED_ROTATE_PROVIDERS))
        raise ValueError(f"Unsupported provider '{provider}'. Use one of: {allowed}")

    if selected == "aws":
        key_id = resource or "<ACCESS_KEY_ID>"
        return RotationPlan(
            provider="aws",
            resource=key_id,
            summary="Disable leaked IAM key, mint replacement, and rotate downstream secrets.",
            commands=(
                f"aws iam update-access-key --access-key-id {key_id} "
                "--status Inactive --user-name <IAM_USER>",
                "aws iam create-access-key --user-name <IAM_USER>",
                "aws secretsmanager put-secret-value --secret-id <SECRET_NAME> "
                "--secret-string '<NEW_SECRET_JSON>'",
            ),
            checks=(
                "aws iam list-access-keys --user-name <IAM_USER>",
                "aws sts get-caller-identity",
            ),
            notes=(
                "Delete inactive leaked keys after rollout succeeds.",
                "Review CloudTrail for suspicious activity.",
            ),
        )

    if selected == "github":
        token_name = resource or "<TOKEN_ALIAS>"
        return RotationPlan(
            provider="github",
            resource=token_name,
            summary="Revoke leaked token and update all GitHub secrets referencing it.",
            commands=(
                "gh auth status",
                "gh secret set <SECRET_NAME> --body '<NEW_TOKEN>' --repo <owner/repo>",
                "gh secret set <SECRET_NAME> --body '<NEW_TOKEN>' --org <org>",
            ),
            checks=(
                "gh secret list --repo <owner/repo>",
                "curl -sS -H 'Authorization: Bearer <NEW_TOKEN>' https://api.github.com/user",
            ),
            notes=(
                "Revoke leaked PAT in https://github.com/settings/tokens",
                "For GitHub App/OAuth tokens, revoke in app settings.",
            ),
        )

    stripe_label = resource or "<STRIPE_KEY_LABEL>"
    return RotationPlan(
        provider="stripe",
        resource=stripe_label,
        summary="Roll Stripe key in dashboard and redeploy all services with new credentials.",
        commands=(
            "gh secret set STRIPE_SECRET_KEY --body '<NEW_KEY>' --repo <owner/repo>",
            "gh secret set STRIPE_SECRET_KEY --body '<NEW_KEY>' --org <org>",
            "curl -sS https://api.stripe.com/v1/account -u '<NEW_KEY>:'",
        ),
        checks=(
            "curl -sS https://api.stripe.com/v1/account -u '<NEW_KEY>:'",
            "keyburn verify --provider stripe --from-env STRIPE_SECRET_KEY",
        ),
        notes=(
            "Roll key from Stripe Dashboard > Developers > API keys.",
            "Monitor payments/refunds/webhooks for suspicious behavior.",
        ),
    )
