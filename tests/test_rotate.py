from __future__ import annotations

import pytest

from keyburn.rotate import build_rotation_plan


def test_build_rotation_plan_aws_contains_expected_commands() -> None:
    plan = build_rotation_plan("aws", resource="AKIA1234567890ABCDEF")
    assert plan.provider == "aws"
    assert "AKIA1234567890ABCDEF" in plan.commands[0]
    assert any("create-access-key" in cmd for cmd in plan.commands)


def test_build_rotation_plan_github_contains_secret_set_commands() -> None:
    plan = build_rotation_plan("github")
    assert plan.provider == "github"
    assert any("gh secret set" in cmd for cmd in plan.commands)


def test_build_rotation_plan_rejects_unsupported_provider() -> None:
    with pytest.raises(ValueError):
        build_rotation_plan("openai")
