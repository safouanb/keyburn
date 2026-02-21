from __future__ import annotations

from pathlib import Path

from keyburn.patterns import Severity
from keyburn.scanner import scan_path, scan_text, should_fail, summarize

# ---------------------------------------------------------------------------
# Existing tests (preserved)
# ---------------------------------------------------------------------------


def test_detects_github_pat(tmp_path: Path) -> None:
    p = tmp_path / "demo.txt"
    # Build the token dynamically so the repo itself doesn't contain a literal
    # PAT-looking string (the scanner is text-based and would flag it).
    token = "ghp_" + ("0123456789" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    p.write_text(f"token={token}\n", encoding="utf-8")

    findings = scan_path(tmp_path)
    assert any(f.pattern_id == "github-pat-classic" for f in findings)
    assert should_fail(findings, fail_on=Severity.high) is True


def test_respects_max_file_size(tmp_path: Path) -> None:
    p = tmp_path / "big.txt"
    p.write_bytes(b"a" * (3 * 1024 * 1024))

    findings = scan_path(tmp_path)
    assert findings == []


# ---------------------------------------------------------------------------
# Pattern detection tests
# ---------------------------------------------------------------------------


def test_detects_aws_access_key_id() -> None:
    text = "aws_key = " + "AKIA" + "1234567890ABCDEF"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert any(f.pattern_id == "aws-access-key-id" for f in findings)


def test_detects_aws_secret_access_key() -> None:
    secret = "A" * 40
    text = f"aws_secret_access_key = '{secret}'"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert any(f.pattern_id == "aws-secret-access-key" for f in findings)


def test_detects_github_fine_grained_pat() -> None:
    token = "github_pat_" + "A1b2C3d4E5f6G7h8I9j0K1l2"
    text = f'TOKEN = "{token}"'
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert any(f.pattern_id == "github-pat-fine-grained" for f in findings)


def test_detects_slack_token() -> None:
    token = "xoxb-" + "1234567890-abcdefghij"
    text = f"SLACK_TOKEN={token}"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert any(f.pattern_id == "slack-token" for f in findings)


def test_detects_slack_webhook() -> None:
    url = (
        "https://hooks.slack.com/services/"
        + "T01234567"
        + "/"
        + "B01234567"
        + "/"
        + "abcdefghijklmnopqrstuv"
    )
    text = f'WEBHOOK = "{url}"'
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert any(f.pattern_id == "slack-webhook" for f in findings)


def test_detects_stripe_live_key() -> None:
    key = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    text = f"STRIPE_KEY={key}"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert any(f.pattern_id == "stripe-secret-live" for f in findings)


def test_detects_stripe_test_key() -> None:
    key = "sk_test_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    text = f"STRIPE_KEY={key}"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert any(f.pattern_id == "stripe-secret-test" for f in findings)
    # test keys are medium severity
    f = next(f for f in findings if f.pattern_id == "stripe-secret-test")
    assert f.severity == Severity.medium


def test_detects_google_api_key() -> None:
    key = "AIza" + "abcdefghijklmnopqrstuvwxyz123456789"
    text = f"GOOGLE_KEY={key}"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert any(f.pattern_id == "google-api-key" for f in findings)


def test_detects_openai_project_key() -> None:
    key = "sk-proj-" + "abcdefghijklmnopqrstuv12345"
    text = f'OPENAI_API_KEY = "{key}"'
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert any(f.pattern_id == "openai-project-key" for f in findings)


def test_detects_anthropic_key() -> None:
    key = "sk-ant-" + "abcdefghij1234567890abcde"
    text = f'API_KEY = "{key}"'
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert any(f.pattern_id == "anthropic-api-key" for f in findings)


def test_detects_groq_key() -> None:
    key = "gsk_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    text = f"GROQ_KEY={key}"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert any(f.pattern_id == "groq-api-key" for f in findings)


def test_detects_huggingface_token() -> None:
    token = "hf_" + "A" * 30
    text = f"HF_TOKEN={token}"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert any(f.pattern_id == "huggingface-token" for f in findings)


def test_detects_sendgrid_key() -> None:
    key = "SG." + "A" * 22 + "." + "B" * 43
    text = f"SENDGRID_KEY={key}"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert any(f.pattern_id == "sendgrid-api-key" for f in findings)


def test_detects_postgres_connection_string() -> None:
    uri = "postgresql://" + "user:p4ssw0rd@" + "db.example.com:5432/mydb"
    text = f'DATABASE_URL = "{uri}"'
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert any(f.pattern_id == "postgres-connection-string" for f in findings)


def test_detects_mongodb_connection_string() -> None:
    uri = "mongodb+srv://" + "admin:secret@" + "cluster0.abc.mongodb.net/db"
    text = f'MONGO = "{uri}"'
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert any(f.pattern_id == "mongodb-connection-string" for f in findings)


def test_detects_private_key_block() -> None:
    text = "-----BEGIN RSA PRIVATE KEY-----"
    findings = scan_text(text=text, rel_path="test.pem", enable_entropy=False)
    assert any(f.pattern_id == "private-key-block" for f in findings)


def test_detects_npm_token() -> None:
    token = "npm_" + "A" * 36
    text = f"NPM_TOKEN={token}"
    findings = scan_text(text=text, rel_path=".npmrc", enable_entropy=False)
    assert any(f.pattern_id == "npm-token" for f in findings)


def test_detects_discord_webhook() -> None:
    url = "https://discord.com/api/webhooks/" + "123456789" + "/" + "abcdef_GHIJKL-mnopqr"
    text = f'WEBHOOK = "{url}"'
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert any(f.pattern_id == "discord-webhook" for f in findings)


def test_detects_jwt_secret() -> None:
    text = 'JWT_SECRET = "my-super-secret-jwt-key-that-is-long"'
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert any(f.pattern_id == "jwt-secret-assignment" for f in findings)


def test_detects_password_assignment() -> None:
    text = 'password = "Hunter2_is_not_secure!"'
    findings = scan_text(text=text, rel_path="config.py", enable_entropy=False)
    assert any(f.pattern_id == "password-assignment" for f in findings)


def test_detects_nextjs_public_secret() -> None:
    text = 'NEXT_PUBLIC_SECRET_KEY = "my_super_secret_value_1234"'
    findings = scan_text(text=text, rel_path=".env.local", enable_entropy=False)
    assert any(f.pattern_id == "nextjs-public-secret" for f in findings)


def test_detects_shopify_access_token() -> None:
    token = "shpat_" + "a" * 32
    text = f"SHOPIFY_TOKEN={token}"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert any(f.pattern_id == "shopify-access-token" for f in findings)


def test_detects_doppler_token() -> None:
    token = "dp.st." + "a" * 40
    text = f"DOPPLER={token}"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert any(f.pattern_id == "doppler-token" for f in findings)


# ---------------------------------------------------------------------------
# Remediation field tests
# ---------------------------------------------------------------------------


def test_findings_include_remediation() -> None:
    key = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    text = f"STRIPE_KEY={key}"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    f = next(f for f in findings if f.pattern_id == "stripe-secret-live")
    assert f.remediation
    assert "dashboard.stripe.com" in f.remediation


def test_remediation_in_to_dict() -> None:
    key = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    text = f"STRIPE_KEY={key}"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    f = next(f for f in findings if f.pattern_id == "stripe-secret-live")
    d = f.to_dict()
    assert "remediation" in d


# ---------------------------------------------------------------------------
# False positive tests (must NOT match)
# ---------------------------------------------------------------------------


def test_no_false_positive_on_placeholder() -> None:
    text = 'API_KEY = "your-api-key-here"'
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    # Generic patterns might match but should not flag known placeholders
    # The important thing is no high-severity pattern fires
    high = [f for f in findings if f.severity == Severity.high]
    assert len(high) == 0


def test_no_false_positive_on_empty_string() -> None:
    text = 'SECRET_KEY = ""'
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert len(findings) == 0


def test_no_false_positive_on_comment() -> None:
    text = "# AKIA is the prefix for AWS access keys"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    # Should not match unless followed by 16 uppercase alphanumeric chars
    assert not any(f.pattern_id == "aws-access-key-id" for f in findings)


# ---------------------------------------------------------------------------
# Summarize and should_fail tests
# ---------------------------------------------------------------------------


def test_summarize_counts() -> None:
    key = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    text = f"STRIPE_KEY={key}"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    summ = summarize(findings)
    assert summ["total"] >= 1
    assert summ["high"] >= 1


def test_should_fail_respects_threshold() -> None:
    # Medium-severity finding should not fail on high threshold
    key = "sk_test_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    text = f"STRIPE_KEY={key}"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    assert should_fail(findings, fail_on=Severity.high) is False
    assert should_fail(findings, fail_on=Severity.medium) is True


# ---------------------------------------------------------------------------
# Deduplication test
# ---------------------------------------------------------------------------


def test_deduplicates_same_secret_on_same_line() -> None:
    key = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    # Same key appearing twice on the same line should deduplicate
    text = f"KEY1={key}  KEY2={key}"
    findings = scan_text(text=text, rel_path="test.py", enable_entropy=False)
    stripe_findings = [f for f in findings if f.pattern_id == "stripe-secret-live"]
    assert len(stripe_findings) == 1


# ---------------------------------------------------------------------------
# Scan path tests
# ---------------------------------------------------------------------------


def test_skips_binary_files(tmp_path: Path) -> None:
    p = tmp_path / "binary.dat"
    p.write_bytes(b"\x00" * 100)
    findings = scan_path(tmp_path)
    assert findings == []


def test_scans_single_file(tmp_path: Path) -> None:
    p = tmp_path / "single.txt"
    token = "ghp_" + ("0123456789" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    p.write_text(f"token={token}\n", encoding="utf-8")

    findings = scan_path(p)
    assert any(f.pattern_id == "github-pat-classic" for f in findings)
