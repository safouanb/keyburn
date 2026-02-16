from __future__ import annotations

from keyburn.entropy import scan_line_entropy, shannon_entropy
from keyburn.scanner import scan_text

# ---------------------------------------------------------------------------
# Shannon entropy unit tests
# ---------------------------------------------------------------------------


def test_entropy_of_empty_string() -> None:
    assert shannon_entropy("") == 0.0


def test_entropy_of_single_char() -> None:
    assert shannon_entropy("aaaa") == 0.0


def test_entropy_of_high_randomness() -> None:
    # A string with many distinct chars should have high entropy
    val = "aB3dE5gH7jK9mN1pQ3sT5uW7yZ0bC2eF"
    ent = shannon_entropy(val)
    assert ent > 4.0


def test_entropy_of_low_randomness() -> None:
    val = "aaaaabbbbbccccc"
    ent = shannon_entropy(val)
    assert ent < 2.0


# ---------------------------------------------------------------------------
# Line-level entropy detection
# ---------------------------------------------------------------------------


def test_detects_high_entropy_secret_assignment() -> None:
    # High-entropy value assigned to a secret-looking variable
    value = "aB3dE5gH7jK9mN1pQ3sT5uW7yZ0bC2eF"
    line = f'SECRET_KEY = "{value}"'
    findings = scan_line_entropy(line, 1)
    assert len(findings) >= 1
    assert findings[0].var_name == "SECRET_KEY"


def test_detects_high_entropy_api_key() -> None:
    value = "xY9kL2mN5pQ8rS1tU4vW7zA0bC3dE6fG"
    line = f'my_api_key = "{value}"'
    findings = scan_line_entropy(line, 1)
    assert len(findings) >= 1


def test_ignores_non_secret_variable() -> None:
    # Variable name doesn't suggest a secret
    value = "aB3dE5gH7jK9mN1pQ3sT5uW7yZ0bC2eF"
    line = f'username = "{value}"'
    findings = scan_line_entropy(line, 1)
    assert len(findings) == 0


def test_ignores_short_values() -> None:
    line = 'SECRET_KEY = "abc123"'
    findings = scan_line_entropy(line, 1)
    assert len(findings) == 0


def test_ignores_low_entropy_secret() -> None:
    # Low entropy value, even with secret variable name
    line = 'SECRET_KEY = "aaaaaaaaaaaaaaaa"'
    findings = scan_line_entropy(line, 1)
    assert len(findings) == 0


def test_ignores_uuid_in_secret_var() -> None:
    line = 'SECRET_KEY = "550e8400-e29b-41d4-a716-446655440000"'
    findings = scan_line_entropy(line, 1)
    assert len(findings) == 0


# ---------------------------------------------------------------------------
# Integration with scanner
# ---------------------------------------------------------------------------


def test_entropy_findings_in_scan_text() -> None:
    # Use a variable name that triggers entropy but NOT the generic-secret pattern
    # (which uses uppercase SECRET). Lowercase "auth_token" hits entropy keywords.
    value = "aB3dE5gH7jK9mN1pQ3sT5uW7yZ0bC2eF"
    text = f'my_auth_token = "{value}"'
    findings = scan_text(text=text, rel_path="config.py", enable_entropy=True)
    entropy_findings = [f for f in findings if f.pattern_id.startswith("entropy-")]
    assert len(entropy_findings) >= 1
    assert entropy_findings[0].remediation


def test_entropy_disabled() -> None:
    value = "aB3dE5gH7jK9mN1pQ3sT5uW7yZ0bC2eF"
    text = f'MY_SECRET_TOKEN = "{value}"'
    findings = scan_text(text=text, rel_path="config.py", enable_entropy=False)
    entropy_findings = [f for f in findings if f.pattern_id.startswith("entropy-")]
    assert len(entropy_findings) == 0
