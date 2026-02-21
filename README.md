# keyburn

**Secret scanner built for the AI coding era.**

Cursor, Copilot, and Lovable write code fast. Sometimes too fast — hardcoded API keys, database URLs, and JWT secrets end up committed before anyone notices. Keyburn catches them before they ship.

- **57 detection patterns** — AWS, OpenAI, Anthropic, Stripe, Supabase, GitHub, Slack, and more
- **Shannon entropy analysis** — catches secrets that don't match a known pattern
- **Actionable remediation hints** — tells you exactly how to fix each finding, not just that something's wrong
- **Framework-aware** — knows that `NEXT_PUBLIC_SECRET_KEY` is exposed to the browser, that Supabase `service_role` keys bypass RLS, etc.
- **Zero noise escape hatches** — `# keyburn:ignore`, allowlists, baselines, per-path excludes
- **CI-native** — text/JSON/SARIF output, GitHub code scanning integration, fail threshold per severity

---

## Install

```bash
pip install keyburn
# or, zero-install:
pipx run keyburn scan .
```

## Quickstart

```bash
# Scan current directory
keyburn scan .

# Scan and fail CI on any high-severity finding
keyburn scan . --fail-on high

# Only scan files changed in this PR
keyburn scan . --diff origin/main

# Only scan staged files (pre-commit)
keyburn scan . --pre-commit

# Output SARIF for GitHub code scanning
keyburn scan . --format sarif --out keyburn.sarif
```

## GitHub Action

Add this to any workflow — it scans on every push/PR and uploads findings to GitHub code scanning:

```yaml
- name: Scan for secrets
  uses: safouanb/keyburn@v0
```

Or with options:

```yaml
- name: Scan for secrets
  uses: safouanb/keyburn@v0
  with:
    fail_on: high          # low | medium | high (default: high)
    format: sarif          # text | json | sarif (default: sarif)
    upload_sarif: "true"   # upload to GitHub code scanning (default: true)
    comment_pr: "true"     # sticky PR comment summary (default: false)
```

Full workflow example:

```yaml
name: Secret scan

on: [push, pull_request]

jobs:
  secrets:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # required for SARIF upload
      pull-requests: write    # required if comment_pr=true
    steps:
      - uses: actions/checkout@v4
      - uses: safouanb/keyburn@v0
        with:
          fail_on: high
          comment_pr: "true"
```

## Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/safouanb/keyburn
    rev: v0.1.2
    hooks:
      - id: keyburn
```

Or use the CLI directly in a git hook:

```bash
# .git/hooks/pre-commit
#!/bin/sh
keyburn scan . --pre-commit --fail-on high
```

## Suppressing false positives

**Inline, for a single line:**

```python
EXAMPLE_KEY = "not_a_real_secret_for_docs"  # keyburn:ignore
```

**Allowlist by regex in `keyburn.toml`:**

```toml
[allowlist]
regex = [
  "^sk_test_",        # all Stripe test keys
  "^EXAMPLE_KEY_",   # placeholder values in docs
]
```

**Baseline — accept current state, catch new ones:**

```bash
# Run once to write the baseline
keyburn scan . --baseline baseline.json --update-baseline

# Future scans only alert on NEW findings
keyburn scan . --baseline baseline.json --fail-on high
```

**Skip files or directories:**

```toml
[scan]
exclude_paths = ["tests/fixtures/**", "docs/examples/**"]
exclude_dirs  = [".venv", "node_modules"]
```

**Disable specific rules:**

```toml
[scan]
disable_rules = ["stripe-secret-test", "entropy"]
```

## Configuration (`keyburn.toml`)

Drop a `keyburn.toml` in your repo root (see `keyburn.toml.example`):

```toml
[scan]
max_file_size_bytes = 2097152
exclude_dirs        = [".venv", "node_modules", "dist"]
exclude_paths       = ["tests/fixtures/**"]
disable_rules       = []
respect_gitignore   = true   # skip files in .gitignore (default: true)

[allowlist]
regex = []
```

## What it detects

| Category | Providers |
|---|---|
| AI APIs | OpenAI, Anthropic, Groq, HuggingFace, Replicate, Cohere |
| Cloud | AWS (key + secret + session), GCP, Firebase |
| Payments | Stripe (live + test + restricted) |
| Auth | GitHub PATs (classic + fine-grained), OAuth tokens, Clerk, Auth0 |
| Comms | Slack (tokens + webhooks), Twilio, SendGrid, Mailgun, Discord, Telegram |
| Database | PostgreSQL, MySQL, MongoDB, Redis (connection strings) |
| Infra | Heroku, Vercel, Netlify, Doppler, Sentry |
| E-commerce | Shopify |
| Packages | npm, PyPI tokens |
| Framework | `NEXT_PUBLIC_` secrets, Supabase service role vs anon key |
| Generic | Hardcoded passwords, JWT secrets, PEM keys, `.env` pasted into source |
| Entropy | High-entropy strings assigned to secret-looking variables |

## Output formats

**Text** (default) — rich panels with remediation hints per finding:

```
╭─ HIGH  Stripe Secret Key (live) ────────────────────────────────╮
│   File: src/payments.js:12:20                                    │
│   Rule: stripe-secret-live                                       │
│   Match: sk_l****************************1234                    │
│                                                                  │
│   How to fix: This is a LIVE Stripe key — it can charge real     │
│   cards. Roll it immediately at dashboard.stripe.com/apikeys.    │
│   Use STRIPE_SECRET_KEY env var instead.                         │
╰──────────────────────────────────────────────────────────────────╯
```

**JSON** — machine-readable with full finding metadata:

```bash
keyburn scan . --format json | jq '.summary'
```

**SARIF** — GitHub code scanning compatible:

```bash
keyburn scan . --format sarif --out keyburn.sarif
```

## Git history scanning

Scan the last N commits for secrets that were added then "deleted":

```bash
keyburn scan --history 50    # last 50 commits
keyburn scan --history all   # full history (slow on large repos)
```

## Precision benchmark

Track scanner noise over time against real OSS repositories:

```bash
python scripts/benchmark_precision.py
```

Results are written to:

- `benchmarks/results/latest.json`
- `benchmarks/results/latest.md`

CI can run this weekly via `.github/workflows/precision-benchmark.yml`.

## Open-core

The scanner and all detection rules are open-source (Apache-2.0). Dashboards, Slack/email alerting, and one-click credential rotation live in a separate hosted product.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). New detectors: open an issue with the provider, a redacted example, expected severity, and known false positives.

## License

Apache-2.0. See [LICENSE](LICENSE).
