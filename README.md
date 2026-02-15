# keyburn

Stop secrets from shipping. Local-first secret scanning for GitHub Actions and CI.

> Status: WIP. Repo scaffolding is in place. The scanner + GitHub Action land next.

Maintainer: [@saf0uan_](https://x.com/saf0uan_)

## What It Will Be

Keyburn is a **local-first** secret scanner for CI and GitHub Actions. The OSS core is a CLI that:

- Scans files for common credential/token formats (high-signal regex patterns).
- Outputs `text`, `json`, or `sarif` (SARIF plugs into GitHub code scanning).
- Fails CI based on a severity threshold.

## Why

Secrets leaks are the most boring way to have a very bad week.
Keyburn is designed to be the fire alarm you actually keep turned on.

## Principles

- Local-first by default: your code stays on the runner.
- No black boxes: detection rules are readable and reviewable.
- Low-noise: patterns should be high-signal and tested for false positives.

## Open-Core

This repository is the open-source scanner + GitHub Action.
Dashboards, alerting, and credential rotation are intended to live in a separate (hosted) product.

## Roadmap

- CLI scanner: scan a path and return structured output (`json`/`sarif`)
- GitHub Action: scan on PR/push, optionally upload SARIF
- Config: excludes + allowlists (`keyburn.toml`)
- Opt-in remote classification (off by default)

## Contributing

See `CONTRIBUTING.md`.

## Security

See `SECURITY.md`.

## License

Apache-2.0. See `LICENSE`.

## Notes

- Any “AI-assisted” classification must be opt-in; you generally should not ship source code off-box by default.
- “Rotation bot” integrations are the real wedge for paid plans; scanner-only is crowded (GitHub Advanced Security, GitGuardian, TruffleHog, Gitleaks).
