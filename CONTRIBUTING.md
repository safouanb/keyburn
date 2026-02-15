# Contributing

Thanks for the help. Keyburn is a security tool: correctness and low-noise behavior matter.

## Guidelines

- Never paste real secrets into issues/PRs/logs. Redact aggressively.
- Prefer high-signal patterns. False positives will get rules removed.
- Keep changes small and tested.

## How To Help

- **New detector**: open an issue with the provider/secret type, a redacted example, expected severity, and common false positives.
- **Rule PR**: include a regex, a minimal test corpus, and examples that must not match.
- **Docs**: clearer docs beat clever docs. If something confuses you, fix it.

## Security

If you find a security issue in the project itself, follow `SECURITY.md` for private disclosure.
