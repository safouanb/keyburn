from __future__ import annotations

from keyburn import verify as verify_mod


def test_infer_provider_stripe() -> None:
    key = "sk_live_" + "a" * 24
    assert verify_mod.infer_provider(key) == "stripe"


def test_infer_provider_github() -> None:
    token = "ghp_" + "a" * 36
    assert verify_mod.infer_provider(token) == "github"


def test_infer_provider_openai_project() -> None:
    token = "sk-proj-" + "abc123" * 5
    assert verify_mod.infer_provider(token) == "openai"


def test_infer_provider_anthropic() -> None:
    token = "sk-ant-" + "a" * 24
    assert verify_mod.infer_provider(token) == "anthropic"


def test_infer_provider_groq() -> None:
    token = "gsk_" + "a" * 24
    assert verify_mod.infer_provider(token) == "groq"


def test_verify_auto_unknown_provider() -> None:
    result = verify_mod.verify_secret("not-a-real-token", provider="auto")
    assert result.status == "unknown"
    assert result.provider == "unknown"


def test_verify_openai_valid(monkeypatch) -> None:
    def fake_request(url: str, *, headers: dict[str, str], timeout: float) -> tuple[int, str]:
        assert url == "https://api.openai.com/v1/models"
        assert headers["Authorization"].startswith("Bearer ")
        assert timeout == 3.0
        return 200, "{}"

    monkeypatch.setattr(verify_mod, "_request", fake_request)

    result = verify_mod.verify_secret("sk-proj-abc123", provider="openai", timeout=3.0)
    assert result.status == "valid"
    assert result.provider == "openai"
    assert result.confidence == 95


def test_verify_openai_invalid(monkeypatch) -> None:
    def fake_request(url: str, *, headers: dict[str, str], timeout: float) -> tuple[int, str]:
        return 401, '{"error": {"message": "Invalid API key"}}'

    monkeypatch.setattr(verify_mod, "_request", fake_request)

    result = verify_mod.verify_secret("sk-proj-abc123", provider="openai")
    assert result.status == "invalid"
    assert "Invalid API key" in result.reason


def test_verify_anthropic_valid(monkeypatch) -> None:
    def fake_request(url: str, *, headers: dict[str, str], timeout: float) -> tuple[int, str]:
        assert url == "https://api.anthropic.com/v1/models"
        assert headers["x-api-key"].startswith("sk-ant-")
        return 200, "{}"

    monkeypatch.setattr(verify_mod, "_request", fake_request)

    result = verify_mod.verify_secret("sk-ant-" + "a" * 24, provider="anthropic")
    assert result.status == "valid"
    assert result.provider == "anthropic"


def test_verify_groq_invalid(monkeypatch) -> None:
    def fake_request(url: str, *, headers: dict[str, str], timeout: float) -> tuple[int, str]:
        assert url == "https://api.groq.com/openai/v1/models"
        return 401, '{"error": {"message": "Invalid API key"}}'

    monkeypatch.setattr(verify_mod, "_request", fake_request)

    result = verify_mod.verify_secret("gsk_" + "a" * 24, provider="groq")
    assert result.status == "invalid"
    assert result.provider == "groq"


def test_verify_github_unknown_on_403(monkeypatch) -> None:
    def fake_request(url: str, *, headers: dict[str, str], timeout: float) -> tuple[int, str]:
        return 403, '{"message": "Resource not accessible by personal access token"}'

    monkeypatch.setattr(verify_mod, "_request", fake_request)

    result = verify_mod.verify_secret("ghp_" + "a" * 36, provider="github")
    assert result.status == "unknown"
    assert result.http_status == 403


def test_verify_stripe_test_key_priority(monkeypatch) -> None:
    def fake_request(url: str, *, headers: dict[str, str], timeout: float) -> tuple[int, str]:
        return 200, "{}"

    monkeypatch.setattr(verify_mod, "_request", fake_request)

    result = verify_mod.verify_secret("sk_test_" + "a" * 24, provider="stripe")
    assert result.status == "valid"
    assert result.priority == "medium"


def test_verify_network_error(monkeypatch) -> None:
    def fake_request(url: str, *, headers: dict[str, str], timeout: float) -> tuple[int, str]:
        raise RuntimeError("connection refused")

    monkeypatch.setattr(verify_mod, "_request", fake_request)

    result = verify_mod.verify_secret("ghp_" + "a" * 36, provider="github")
    assert result.status == "error"
    assert "connection refused" in result.reason


def test_verify_unsupported_provider_error_lists_new_providers() -> None:
    result = verify_mod.verify_secret("abc", provider="not-real")
    assert result.status == "error"
    assert "anthropic" in result.reason
    assert "groq" in result.reason
