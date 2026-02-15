# Security Policy

## Reporting a Vulnerability

Please do not open a public issue for security vulnerabilities.

1. Use GitHub Security Advisories for private disclosure (preferred):
   - Go to the repository's "Security" tab
   - Click "Report a vulnerability"
2. If that is not available, contact the maintainers privately.

## Scope

This project is a best-effort secret scanner. It may produce false positives and false negatives.
Always rotate/revoke exposed credentials and remove them from git history.

## Data Handling

The open-source scanner runs locally in your CI runner.
If you add optional remote classification in the future, it must be opt-in and documented clearly.

