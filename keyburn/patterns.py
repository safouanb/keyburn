from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from re import Pattern


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
    remediation: str = ""
    secret_group: int = 0


def _re(pattern: str, *, flags: int = re.IGNORECASE) -> Pattern[str]:
    return re.compile(pattern, flags)


# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------

PATTERNS: list[SecretPattern] = [
    # ------------------------------------------------------------------
    # AWS
    # ------------------------------------------------------------------
    SecretPattern(
        id="aws-access-key-id",
        title="AWS Access Key ID",
        description="Looks like an AWS access key id (AKIA/ASIA...).",
        severity=Severity.high,
        category="aws",
        regex=_re(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", flags=0),
        remediation=(
            "Move the key to an environment variable (AWS_ACCESS_KEY_ID) "
            "and load it from your shell or a .env file. "
            "Rotate this key immediately in the AWS IAM console."
        ),
    ),
    SecretPattern(
        id="aws-secret-access-key",
        title="AWS Secret Access Key",
        description="Looks like an AWS secret access key assignment.",
        severity=Severity.high,
        category="aws",
        regex=_re(r"\baws_secret_access_key\b\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        secret_group=1,
        remediation=(
            "Never hardcode AWS secret keys. Use environment variables or "
            "~/.aws/credentials. Rotate this key in the AWS IAM console now."
        ),
    ),
    SecretPattern(
        id="aws-session-token",
        title="AWS Session Token",
        description="Looks like an AWS session token assignment.",
        severity=Severity.high,
        category="aws",
        regex=_re(r"\baws_session_token\b\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?"),
        secret_group=1,
        remediation=(
            "Session tokens are temporary but still sensitive. "
            "Use environment variables or IAM roles instead of hardcoding."
        ),
    ),
    # ------------------------------------------------------------------
    # GitHub
    # ------------------------------------------------------------------
    SecretPattern(
        id="github-pat-classic",
        title="GitHub PAT (classic)",
        description="Looks like a GitHub personal access token (classic).",
        severity=Severity.high,
        category="github",
        regex=_re(r"\bghp_[A-Za-z0-9]{36}\b", flags=0),
        remediation=(
            "Revoke this token at github.com/settings/tokens and create a new one. "
            "Store it in a GITHUB_TOKEN environment variable or repo secret."
        ),
    ),
    SecretPattern(
        id="github-pat-fine-grained",
        title="GitHub PAT (fine-grained)",
        description="Looks like a GitHub fine-grained personal access token.",
        severity=Severity.high,
        category="github",
        regex=_re(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", flags=0),
        remediation=(
            "Revoke this token at github.com/settings/tokens and create a new one. "
            "Use GitHub Actions secrets for CI workflows."
        ),
    ),
    SecretPattern(
        id="github-oauth-secret",
        title="GitHub OAuth App Secret",
        description="Looks like a GitHub OAuth client secret.",
        severity=Severity.high,
        category="github",
        regex=_re(r"\bgho_[A-Za-z0-9]{36}\b", flags=0),
        remediation=(
            "Regenerate the OAuth secret in your GitHub OAuth app settings. "
            "Store it in an environment variable, never in source code."
        ),
    ),
    SecretPattern(
        id="github-app-token",
        title="GitHub App Token",
        description="Looks like a GitHub App installation token.",
        severity=Severity.high,
        category="github",
        regex=_re(r"\bghu_[A-Za-z0-9]{36}\b", flags=0),
        remediation=(
            "GitHub App tokens are short-lived but still sensitive. Use secrets management."
        ),
    ),
    SecretPattern(
        id="github-refresh-token",
        title="GitHub Refresh Token",
        description="Looks like a GitHub refresh token.",
        severity=Severity.high,
        category="github",
        regex=_re(r"\bghr_[A-Za-z0-9]{36}\b", flags=0),
        remediation="Revoke this token immediately and regenerate via your OAuth flow.",
    ),
    # ------------------------------------------------------------------
    # Slack
    # ------------------------------------------------------------------
    SecretPattern(
        id="slack-token",
        title="Slack Token",
        description="Looks like a Slack token (xoxb/xoxp/xoxa/xoxr).",
        severity=Severity.high,
        category="slack",
        regex=_re(r"\bxox[abopr]-[0-9A-Za-z-]{10,}\b", flags=0),
        remediation=(
            "Revoke the token in your Slack app settings. "
            "Use environment variables: SLACK_BOT_TOKEN or SLACK_TOKEN."
        ),
    ),
    SecretPattern(
        id="slack-webhook",
        title="Slack Webhook URL",
        description="Looks like a Slack incoming webhook URL.",
        severity=Severity.medium,
        category="slack",
        regex=_re(
            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
            flags=0,
        ),
        remediation=(
            "Revoke this webhook in Slack and create a new one. "
            "Store the URL in an environment variable (SLACK_WEBHOOK_URL)."
        ),
    ),
    # ------------------------------------------------------------------
    # Stripe
    # ------------------------------------------------------------------
    SecretPattern(
        id="stripe-secret-live",
        title="Stripe Secret Key (live)",
        description="Looks like a Stripe live secret key.",
        severity=Severity.high,
        category="stripe",
        regex=_re(r"\bsk_live_[0-9a-zA-Z]{20,}\b", flags=0),
        remediation=(
            "This is a LIVE Stripe key — it can charge real cards. "
            "Roll it immediately at dashboard.stripe.com/apikeys. "
            "Use STRIPE_SECRET_KEY env var instead."
        ),
    ),
    SecretPattern(
        id="stripe-secret-test",
        title="Stripe Secret Key (test)",
        description="Looks like a Stripe test secret key.",
        severity=Severity.medium,
        category="stripe",
        regex=_re(r"\bsk_test_[0-9a-zA-Z]{20,}\b", flags=0),
        remediation=(
            "Even test keys should not be in code. "
            "Use STRIPE_SECRET_KEY env var. Roll at dashboard.stripe.com/apikeys."
        ),
    ),
    SecretPattern(
        id="stripe-restricted-key",
        title="Stripe Restricted Key",
        description="Looks like a Stripe restricted API key.",
        severity=Severity.high,
        category="stripe",
        regex=_re(r"\brk_live_[0-9a-zA-Z]{20,}\b", flags=0),
        remediation="Roll this key at dashboard.stripe.com/apikeys and use env vars.",
    ),
    # ------------------------------------------------------------------
    # Google / GCP / Firebase
    # ------------------------------------------------------------------
    SecretPattern(
        id="google-api-key",
        title="Google API Key",
        description="Looks like a Google API key (AIza...).",
        severity=Severity.high,
        category="gcp",
        regex=_re(r"\bAIza[0-9A-Za-z\-_]{35}\b", flags=0),
        remediation=(
            "Restrict this key in the Google Cloud Console (APIs & Services > Credentials). "
            "Use application default credentials or env vars instead."
        ),
    ),
    SecretPattern(
        id="gcp-service-account",
        title="GCP Service Account Key",
        description="Looks like a GCP service account private key ID.",
        severity=Severity.high,
        category="gcp",
        regex=_re(r'"private_key_id"\s*:\s*"([a-f0-9]{40})"'),
        secret_group=1,
        remediation=(
            "Delete this service account key in GCP IAM and create a new one. "
            "Use workload identity federation instead of JSON key files."
        ),
    ),
    SecretPattern(
        id="firebase-service-role",
        title="Firebase/Supabase Service Role Key in Code",
        description="Looks like a service role or admin key assigned in source code.",
        severity=Severity.high,
        category="firebase",
        regex=_re(
            r"\b(service[_-]?role[_-]?key|SUPABASE_SERVICE_ROLE_KEY|FIREBASE_ADMIN_SDK)\b"
            r"\s*[:=]\s*['\"]([A-Za-z0-9._\-]{20,})['\"]"
        ),
        secret_group=2,
        remediation=(
            "Service role keys have admin access — never put them in client code. "
            "Use environment variables and keep them server-side only."
        ),
    ),
    # ------------------------------------------------------------------
    # OpenAI / AI providers
    # ------------------------------------------------------------------
    SecretPattern(
        id="openai-api-key",
        title="OpenAI API Key",
        description="Looks like an OpenAI API key (sk-...).",
        severity=Severity.high,
        category="ai",
        regex=_re(r"\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b", flags=0),
        remediation=(
            "Revoke this key at platform.openai.com/api-keys. "
            "Use OPENAI_API_KEY env var. Anyone with this key can run up your bill."
        ),
    ),
    SecretPattern(
        id="openai-api-key-assignment",
        title="OpenAI API Key Assignment",
        description="Looks like an OpenAI API key in a typical env/setting assignment.",
        severity=Severity.high,
        category="ai",
        regex=_re(
            r"\b(openai[_-]?api[_-]?key|OPENAI_API_KEY)\b\s*[:=]\s*['\"]?(sk-[A-Za-z0-9]{20,})['\"]?"
        ),
        secret_group=2,
        remediation=(
            "Move to .env file and load with dotenv. Revoke at platform.openai.com/api-keys."
        ),
    ),
    SecretPattern(
        id="openai-project-key",
        title="OpenAI Project API Key",
        description="Looks like an OpenAI project-scoped API key (sk-proj-...).",
        severity=Severity.high,
        category="ai",
        regex=_re(r"\bsk-proj-[A-Za-z0-9\-_]{20,}\b", flags=0),
        remediation=(
            "Revoke at platform.openai.com/api-keys. "
            "Use OPENAI_API_KEY env var. Never hardcode in source files."
        ),
    ),
    SecretPattern(
        id="anthropic-api-key",
        title="Anthropic API Key",
        description="Looks like an Anthropic (Claude) API key.",
        severity=Severity.high,
        category="ai",
        regex=_re(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b", flags=0),
        remediation=("Revoke at console.anthropic.com. Use ANTHROPIC_API_KEY env var."),
    ),
    SecretPattern(
        id="groq-api-key",
        title="Groq API Key",
        description="Looks like a Groq API key.",
        severity=Severity.high,
        category="ai",
        regex=_re(r"\bgsk_[A-Za-z0-9]{20,}\b", flags=0),
        remediation="Revoke at console.groq.com. Use GROQ_API_KEY env var.",
    ),
    SecretPattern(
        id="huggingface-token",
        title="Hugging Face Token",
        description="Looks like a Hugging Face access token.",
        severity=Severity.high,
        category="ai",
        regex=_re(r"\bhf_[A-Za-z0-9]{30,}\b", flags=0),
        remediation="Revoke at huggingface.co/settings/tokens. Use HF_TOKEN env var.",
    ),
    SecretPattern(
        id="replicate-api-key",
        title="Replicate API Key",
        description="Looks like a Replicate API token.",
        severity=Severity.high,
        category="ai",
        regex=_re(r"\br8_[A-Za-z0-9]{36,}\b", flags=0),
        remediation="Revoke at replicate.com/account/api-tokens. Use REPLICATE_API_TOKEN env var.",
    ),
    SecretPattern(
        id="cohere-api-key",
        title="Cohere API Key",
        description="Looks like a Cohere API key.",
        severity=Severity.high,
        category="ai",
        regex=_re(r"\b[A-Za-z0-9]{40}\b.*cohere|cohere.*\b[A-Za-z0-9]{40}\b"),
        remediation="Revoke at dashboard.cohere.com/api-keys. Use CO_API_KEY env var.",
    ),
    # ------------------------------------------------------------------
    # Supabase
    # ------------------------------------------------------------------
    SecretPattern(
        id="supabase-service-role",
        title="Supabase Service Role Key",
        description="Supabase service_role key — has full database access, bypasses RLS.",
        severity=Severity.high,
        category="supabase",
        regex=_re(
            r"\b(SUPABASE_SERVICE_ROLE_KEY|service_role)\b\s*[:=]\s*['\"]?"
            r"(eyJ[A-Za-z0-9_\-]{50,}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)['\"]?"
        ),
        secret_group=2,
        remediation=(
            "This key bypasses Row Level Security — it should NEVER be in client/frontend code. "
            "Keep it server-side only. Regenerate in Supabase dashboard > Settings > API."
        ),
    ),
    SecretPattern(
        id="supabase-anon-key-server",
        title="Supabase Anon Key in Server Code",
        description=(
            "Supabase anon key found in a server-side file where service_role may be intended."
        ),
        severity=Severity.low,
        category="supabase",
        regex=_re(
            r"\b(SUPABASE_ANON_KEY|supabase_anon)\b\s*[:=]\s*['\"]?"
            r"(eyJ[A-Za-z0-9_\-]{50,})['\"]?"
        ),
        secret_group=2,
        remediation=(
            "Supabase anon keys are designed to be public, but double-check your "
            "Row Level Security policies are properly configured."
        ),
    ),
    # ------------------------------------------------------------------
    # Next.js / Vercel framework-aware
    # ------------------------------------------------------------------
    SecretPattern(
        id="nextjs-public-secret",
        title="Secret in NEXT_PUBLIC_ Variable",
        description=(
            "A secret-looking value in a NEXT_PUBLIC_ env var — these are exposed to the browser."
        ),
        severity=Severity.high,
        category="framework",
        regex=_re(
            r"\bNEXT_PUBLIC_[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE)[A-Z_]*\b"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-/.+=]{10,})['\"]?"
        ),
        secret_group=1,
        remediation=(
            "NEXT_PUBLIC_ vars are bundled into client JS and visible to everyone. "
            "Remove the NEXT_PUBLIC_ prefix and access this value server-side only "
            "(API routes, getServerSideProps, server actions)."
        ),
    ),
    # ------------------------------------------------------------------
    # Database connection strings
    # ------------------------------------------------------------------
    SecretPattern(
        id="postgres-connection-string",
        title="PostgreSQL Connection String",
        description="Looks like a PostgreSQL connection URI with embedded credentials.",
        severity=Severity.high,
        category="database",
        regex=_re(r"postgres(?:ql)?://[^:]+:[^@]+@[^/\s]{3,}"),
        remediation=(
            "Move the connection string to DATABASE_URL env var. "
            "Never hardcode database credentials. Use .env + dotenv."
        ),
    ),
    SecretPattern(
        id="mysql-connection-string",
        title="MySQL Connection String",
        description="Looks like a MySQL connection URI with embedded credentials.",
        severity=Severity.high,
        category="database",
        regex=_re(r"mysql://[^:]+:[^@]+@[^/\s]{3,}"),
        remediation="Move to DATABASE_URL env var. Never hardcode database credentials.",
    ),
    SecretPattern(
        id="mongodb-connection-string",
        title="MongoDB Connection String",
        description="Looks like a MongoDB connection URI with embedded credentials.",
        severity=Severity.high,
        category="database",
        regex=_re(r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^/\s]{3,}"),
        remediation="Move to MONGODB_URI env var. Never hardcode database credentials.",
    ),
    SecretPattern(
        id="redis-connection-string",
        title="Redis Connection String",
        description="Looks like a Redis connection URI with embedded credentials.",
        severity=Severity.high,
        category="database",
        regex=_re(r"redis://[^:]*:[^@]+@[^/\s]{3,}"),
        remediation="Move to REDIS_URL env var. Never hardcode credentials.",
    ),
    # ------------------------------------------------------------------
    # Twilio
    # ------------------------------------------------------------------
    SecretPattern(
        id="twilio-api-key",
        title="Twilio API Key",
        description="Looks like a Twilio API key (SK prefix).",
        severity=Severity.high,
        category="twilio",
        regex=_re(r"\bSK[0-9a-fA-F]{32}\b", flags=0),
        remediation=(
            "Revoke at twilio.com/console. Use TWILIO_API_KEY and TWILIO_API_SECRET env vars."
        ),
    ),
    SecretPattern(
        id="twilio-auth-token",
        title="Twilio Auth Token",
        description="Looks like a Twilio auth token assignment.",
        severity=Severity.high,
        category="twilio",
        regex=_re(
            r"\b(twilio[_-]?auth[_-]?token|TWILIO_AUTH_TOKEN)\b\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?"
        ),
        secret_group=2,
        remediation="Rotate in Twilio console. Use TWILIO_AUTH_TOKEN env var.",
    ),
    # ------------------------------------------------------------------
    # SendGrid
    # ------------------------------------------------------------------
    SecretPattern(
        id="sendgrid-api-key",
        title="SendGrid API Key",
        description="Looks like a SendGrid API key.",
        severity=Severity.high,
        category="sendgrid",
        regex=_re(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", flags=0),
        remediation="Revoke at app.sendgrid.com/settings/api_keys. Use SENDGRID_API_KEY env var.",
    ),
    # ------------------------------------------------------------------
    # Mailgun
    # ------------------------------------------------------------------
    SecretPattern(
        id="mailgun-api-key",
        title="Mailgun API Key",
        description="Looks like a Mailgun API key.",
        severity=Severity.high,
        category="mailgun",
        regex=_re(r"\bkey-[0-9a-zA-Z]{32}\b", flags=0),
        remediation="Rotate at app.mailgun.com. Use MAILGUN_API_KEY env var.",
    ),
    # ------------------------------------------------------------------
    # Datadog
    # ------------------------------------------------------------------
    SecretPattern(
        id="datadog-api-key",
        title="Datadog API Key",
        description="Looks like a Datadog API key assignment.",
        severity=Severity.high,
        category="datadog",
        regex=_re(r"\b(DD_API_KEY|datadog[_-]?api[_-]?key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?"),
        secret_group=2,
        remediation="Rotate in Datadog organization settings. Use DD_API_KEY env var.",
    ),
    # ------------------------------------------------------------------
    # npm
    # ------------------------------------------------------------------
    SecretPattern(
        id="npm-token",
        title="npm Access Token",
        description="Looks like an npm access token.",
        severity=Severity.high,
        category="npm",
        regex=_re(r"\bnpm_[A-Za-z0-9]{36}\b", flags=0),
        remediation=(
            "Revoke at npmjs.com/settings/tokens. "
            "Use NPM_TOKEN env var in CI. "
            "This token can publish packages under your name."
        ),
    ),
    # ------------------------------------------------------------------
    # PyPI
    # ------------------------------------------------------------------
    SecretPattern(
        id="pypi-api-token",
        title="PyPI API Token",
        description="Looks like a PyPI API token.",
        severity=Severity.high,
        category="pypi",
        regex=_re(r"\bpypi-[A-Za-z0-9_\-]{50,}\b", flags=0),
        remediation="Revoke at pypi.org/manage/account/token/. Use TWINE_PASSWORD env var.",
    ),
    # ------------------------------------------------------------------
    # Heroku
    # ------------------------------------------------------------------
    SecretPattern(
        id="heroku-api-key",
        title="Heroku API Key",
        description="Looks like a Heroku API key assignment.",
        severity=Severity.high,
        category="heroku",
        regex=_re(
            r"\b(HEROKU_API_KEY|heroku[_-]?api[_-]?key)\b\s*[:=]\s*['\"]?"
            r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['\"]?"
        ),
        secret_group=2,
        remediation="Regenerate at dashboard.heroku.com/account. Use HEROKU_API_KEY env var.",
    ),
    # ------------------------------------------------------------------
    # Shopify
    # ------------------------------------------------------------------
    SecretPattern(
        id="shopify-access-token",
        title="Shopify Access Token",
        description="Looks like a Shopify access token.",
        severity=Severity.high,
        category="shopify",
        regex=_re(r"\bshpat_[A-Fa-f0-9]{32}\b", flags=0),
        remediation="Revoke in Shopify Partners dashboard. Use env var for the token.",
    ),
    SecretPattern(
        id="shopify-shared-secret",
        title="Shopify Shared Secret",
        description="Looks like a Shopify shared secret.",
        severity=Severity.high,
        category="shopify",
        regex=_re(r"\bshpss_[A-Fa-f0-9]{32}\b", flags=0),
        remediation="Rotate in Shopify app settings. Never commit shared secrets.",
    ),
    # ------------------------------------------------------------------
    # Discord
    # ------------------------------------------------------------------
    SecretPattern(
        id="discord-bot-token",
        title="Discord Bot Token",
        description="Looks like a Discord bot token.",
        severity=Severity.high,
        category="discord",
        regex=_re(r"[MN][A-Za-z\d]{23,}\.[A-Za-z\d\-_]{6}\.[A-Za-z\d\-_]{27,}", flags=0),
        remediation=(
            "Regenerate at discord.com/developers/applications. Use DISCORD_TOKEN env var."
        ),
    ),
    SecretPattern(
        id="discord-webhook",
        title="Discord Webhook URL",
        description="Looks like a Discord webhook URL.",
        severity=Severity.medium,
        category="discord",
        regex=_re(r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+", flags=0),
        remediation="Delete this webhook and create a new one. Store URL in env var.",
    ),
    # ------------------------------------------------------------------
    # Telegram
    # ------------------------------------------------------------------
    SecretPattern(
        id="telegram-bot-token",
        title="Telegram Bot Token",
        description="Looks like a Telegram bot token.",
        severity=Severity.high,
        category="telegram",
        regex=_re(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b", flags=0),
        remediation="Revoke via @BotFather on Telegram. Use TELEGRAM_BOT_TOKEN env var.",
    ),
    # ------------------------------------------------------------------
    # JWT / Generic
    # ------------------------------------------------------------------
    SecretPattern(
        id="jwt-secret-assignment",
        title="JWT Secret Assignment",
        description="Looks like a JWT secret being hardcoded.",
        severity=Severity.high,
        category="crypto",
        regex=_re(r"\b(jwt[_-]?secret|JWT_SECRET|jwt[_-]?key)\b\s*[:=]\s*['\"]([^'\"]{8,})['\"]"),
        secret_group=2,
        remediation=(
            "Move JWT secrets to environment variables. "
            "Use a strong random value (32+ chars). Never commit secrets."
        ),
    ),
    SecretPattern(
        id="private-key-block",
        title="Private Key Block",
        description="Looks like a PEM private key block header.",
        severity=Severity.high,
        category="crypto",
        regex=_re(r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----", flags=0),
        remediation=(
            "Private keys should never be in source code. "
            "Use a secrets manager or mount as a file from env/volume."
        ),
    ),
    # ------------------------------------------------------------------
    # Passwords in config
    # ------------------------------------------------------------------
    SecretPattern(
        id="password-assignment",
        title="Hardcoded Password",
        description="Looks like a password hardcoded in a variable assignment.",
        severity=Severity.high,
        category="credentials",
        regex=_re(
            r"\b(password|passwd|db_pass|db_password|admin_password)\b"
            r"\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"
        ),
        secret_group=2,
        remediation=(
            "Never hardcode passwords. Use environment variables or a secrets manager. "
            "If this is a real password, change it immediately."
        ),
    ),
    # ------------------------------------------------------------------
    # Auth0
    # ------------------------------------------------------------------
    SecretPattern(
        id="auth0-client-secret",
        title="Auth0 Client Secret",
        description="Looks like an Auth0 client secret assignment.",
        severity=Severity.high,
        category="auth0",
        regex=_re(
            r"\b(AUTH0_CLIENT_SECRET|auth0[_-]?client[_-]?secret)\b"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{30,})['\"]?"
        ),
        secret_group=2,
        remediation="Rotate in Auth0 dashboard. Use AUTH0_CLIENT_SECRET env var.",
    ),
    # ------------------------------------------------------------------
    # Clerk
    # ------------------------------------------------------------------
    SecretPattern(
        id="clerk-secret-key",
        title="Clerk Secret Key",
        description="Looks like a Clerk secret key.",
        severity=Severity.high,
        category="clerk",
        regex=_re(r"\bsk_live_[A-Za-z0-9]{20,}\b", flags=0),
        remediation=(
            "Rotate in Clerk dashboard. Use CLERK_SECRET_KEY env var. Keep server-side only."
        ),
    ),
    # ------------------------------------------------------------------
    # Vercel
    # ------------------------------------------------------------------
    SecretPattern(
        id="vercel-token",
        title="Vercel Token",
        description="Looks like a Vercel authentication token.",
        severity=Severity.high,
        category="vercel",
        regex=_re(r"\b(VERCEL_TOKEN|vercel[_-]?token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{24,})['\"]?"),
        secret_group=2,
        remediation="Regenerate at vercel.com/account/tokens. Use VERCEL_TOKEN env var.",
    ),
    # ------------------------------------------------------------------
    # Netlify
    # ------------------------------------------------------------------
    SecretPattern(
        id="netlify-token",
        title="Netlify Token",
        description="Looks like a Netlify personal access token.",
        severity=Severity.high,
        category="netlify",
        regex=_re(
            r"\b(NETLIFY_AUTH_TOKEN|netlify[_-]?token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{30,})['\"]?"
        ),
        secret_group=2,
        remediation=(
            "Regenerate at app.netlify.com/user/applications. Use NETLIFY_AUTH_TOKEN env var."
        ),
    ),
    # ------------------------------------------------------------------
    # Doppler
    # ------------------------------------------------------------------
    SecretPattern(
        id="doppler-token",
        title="Doppler Token",
        description="Looks like a Doppler service token.",
        severity=Severity.high,
        category="doppler",
        regex=_re(r"\bdp\.st\.[A-Za-z0-9_\-]{40,}\b", flags=0),
        remediation="Revoke in Doppler dashboard. Ironic — your secrets manager token leaked.",
    ),
    # ------------------------------------------------------------------
    # Sentry
    # ------------------------------------------------------------------
    SecretPattern(
        id="sentry-dsn-secret",
        title="Sentry DSN with Secret",
        description="Looks like a Sentry DSN that includes a secret key.",
        severity=Severity.medium,
        category="sentry",
        regex=_re(r"https://[a-f0-9]{32}:[a-f0-9]{32}@[a-z0-9.]+\.ingest\.sentry\.io/\d+"),
        remediation=(
            "Modern Sentry DSNs don't need the secret part. Use the public DSN format instead."
        ),
    ),
    # ------------------------------------------------------------------
    # Generic hardcoded secrets in env var patterns
    # ------------------------------------------------------------------
    SecretPattern(
        id="generic-secret-assignment",
        title="Hardcoded Secret Assignment",
        description="Looks like a secret value assigned to a variable with 'secret' in the name.",
        severity=Severity.medium,
        category="credentials",
        regex=_re(r"\b([A-Z_]*SECRET[A-Z_]*)\b\s*[:=]\s*['\"]([^'\"\s]{10,})['\"]"),
        secret_group=2,
        remediation=(
            "Move secret values to environment variables or a .env file. "
            "Add .env to .gitignore. Use dotenv to load them."
        ),
    ),
    SecretPattern(
        id="generic-api-key-assignment",
        title="Hardcoded API Key Assignment",
        description="Looks like an API key assigned to a variable with 'api_key' in the name.",
        severity=Severity.medium,
        category="credentials",
        regex=_re(r"\b([A-Z_]*API[_-]?KEY[A-Z_]*)\b\s*[:=]\s*['\"]([^'\"\s]{10,})['\"]"),
        secret_group=2,
        remediation=(
            "Move API keys to environment variables or a .env file. "
            "Never commit them to source control."
        ),
    ),
    # ------------------------------------------------------------------
    # .env file in wrong place
    # ------------------------------------------------------------------
    SecretPattern(
        id="dotenv-inline",
        title="Inline .env Content",
        description="Looks like .env file content pasted directly into source code.",
        severity=Severity.medium,
        category="credentials",
        regex=_re(
            r"^[A-Z_]+(SECRET|KEY|TOKEN|PASSWORD|PASS|CREDENTIAL)[A-Z_]*"
            r"=['\"]?[A-Za-z0-9_\-/.+=]{10,}['\"]?$",
            flags=re.MULTILINE,
        ),
        remediation=(
            "This looks like .env content in a source file. "
            "Move it to a .env file and add .env to your .gitignore."
        ),
    ),
    # ------------------------------------------------------------------
    # Crypto
    # ------------------------------------------------------------------
    SecretPattern(
        id="age-secret-key",
        title="age Secret Key",
        description="Looks like an age encryption secret key.",
        severity=Severity.high,
        category="crypto",
        regex=_re(r"\bAGE-SECRET-KEY-[A-Z0-9]{59}\b", flags=0),
        remediation="Never commit age secret keys. Store in a secure keyring or secrets manager.",
    ),
]
