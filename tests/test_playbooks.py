from __future__ import annotations

from keyburn.patterns import Severity
from keyburn.playbooks import build_incident_playbook


def test_build_incident_playbook_for_stripe_includes_rotation_stub() -> None:
    pb = build_incident_playbook(
        "stripe",
        severity=Severity.high,
        pattern_id="stripe-secret-live",
        risk_score=95,
    )
    assert pb.id == "stripe-key-leak"
    assert "keyburn rotate --provider stripe" in pb.rotation_stub
    assert any("incident" in step.lower() for step in pb.steps)


def test_build_incident_playbook_unknown_provider_has_generic_id() -> None:
    pb = build_incident_playbook(
        "unknown",
        severity=Severity.medium,
        pattern_id="entropy",
        risk_score=55,
    )
    assert pb.id == "generic-key-leak"
    assert pb.rotation_stub == ""
