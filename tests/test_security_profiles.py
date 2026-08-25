import pytest

from cisco_assistant.models import SecurityProfile
from cisco_assistant.profiles import load_cbs250_24t_4x_3_3_0_16_profile
from cisco_assistant.security_profiles import (
    RuleRequirement,
    SecurityProfileError,
    expand_security_profile,
    get_security_profile,
    list_security_profiles,
)


def test_initial_security_profiles_are_versioned():
    profiles = list_security_profiles()
    assert [profile.profile for profile in profiles] == [
        SecurityProfile.LAB,
        SecurityProfile.BASIC,
        SecurityProfile.BUSINESS_STANDARD,
        SecurityProfile.STRICT,
    ]
    assert all(profile.version == "1.0.0" for profile in profiles)
    assert all(profile.schema_version == 1 for profile in profiles)
    assert all(profile.rules for profile in profiles)


def test_every_rule_has_explainable_policy_metadata():
    for profile in list_security_profiles():
        for rule in profile.rules:
            assert rule.rule_id
            assert rule.intent
            assert rule.requirement in RuleRequirement
            assert rule.severity.value in {"low", "medium", "high", "critical"}
            assert rule.risk_class in {"R0", "R1", "R2", "W1", "W2", "D"}
            assert rule.explanation
            assert rule.applicability


def test_business_standard_offline_expansion_uses_exact_profile_conservatively():
    device_profile = load_cbs250_24t_4x_3_3_0_16_profile()
    result = expand_security_profile(
        SecurityProfile.BUSINESS_STANDARD,
        device_profile=device_profile,
        require_live_proof=False,
    )

    by_id = {rule.rule_id: rule for rule in result.rules}

    assert by_id["management.ssh"].capability_state == "documented_and_observed"
    assert by_id["management.ssh"].status == "proven"

    assert by_id["management.https"].capability_state == "documented_not_observed"
    assert by_id["management.https"].status == "documented_unproven"

    assert by_id["management.disable_telnet_policy"].capability_state == "policy_only_unmapped"
    assert by_id["management.disable_telnet_policy"].status == "unmapped"

    # Offline design remains usable but explicitly warns about unproven/unmapped controls.
    assert result.valid
    assert any(issue.code == "SECURITY_RULE_CAPABILITY_UNPROVEN" for issue in result.issues)
    assert any(
        issue.code == "SECURITY_RULE_PROVIDER_MAPPING_PENDING"
        for issue in result.issues
    )


def test_business_standard_future_live_precheck_fails_closed_on_unproven_controls():
    device_profile = load_cbs250_24t_4x_3_3_0_16_profile()
    result = expand_security_profile(
        SecurityProfile.BUSINESS_STANDARD,
        device_profile=device_profile,
        require_live_proof=True,
    )

    assert not result.valid
    blocking_codes = {issue.code for issue in result.blocking}
    assert "SECURITY_RULE_CAPABILITY_UNPROVEN" in blocking_codes
    assert "SECURITY_RULE_PROVIDER_MAPPING_PENDING" in blocking_codes


def test_lab_profile_has_lower_policy_pressure_than_business_standard():
    device_profile = load_cbs250_24t_4x_3_3_0_16_profile()
    lab = expand_security_profile(
        SecurityProfile.LAB,
        device_profile=device_profile,
        require_live_proof=False,
    )
    business = expand_security_profile(
        SecurityProfile.BUSINESS_STANDARD,
        device_profile=device_profile,
        require_live_proof=False,
    )

    assert len(lab.rules) < len(business.rules)
    assert not any(rule.rule_id == "management.restrict_sources" for rule in lab.rules)
    assert any(rule.rule_id == "management.restrict_sources" for rule in business.rules)


def test_custom_profile_requires_explicit_definition_instead_of_guessing():
    with pytest.raises(SecurityProfileError, match="CUSTOM"):
        get_security_profile(SecurityProfile.CUSTOM)


def test_expansion_without_device_profile_never_claims_capability_proven():
    result = expand_security_profile(SecurityProfile.BASIC)
    mapped = [rule for rule in result.rules if rule.capability_id is not None]
    assert mapped
    assert all(rule.capability_state == "profile_not_supplied" for rule in mapped)
    assert all(rule.status == "not_checked" for rule in mapped)
