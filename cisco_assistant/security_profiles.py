"""Versioned offline security profiles.

Security profiles are policy data, not command bundles. They expand into explainable rules
and can be checked against an exact ``DeviceProfile`` without generating or executing CLI.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .models import CapabilityState, SecurityProfile
from .profiles import DeviceProfile
from .validation import ValidationIssue, ValidationSeverity


SECURITY_PROFILE_SCHEMA_VERSION = 1


class SecurityProfileError(ValueError):
    """Raised when a security profile or expansion request is invalid."""


class RuleRequirement(str, Enum):
    REQUIRED = "required"
    RECOMMENDED = "recommended"
    CONDITIONAL = "conditional"


class RuleSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class SecurityRuleDefinition:
    rule_id: str
    intent: str
    requirement: RuleRequirement | str
    severity: RuleSeverity | str
    risk_class: str
    capability_id: str | None
    explanation: str
    applicability: str = "always"

    def __post_init__(self) -> None:
        for field_name in ("rule_id", "intent", "risk_class", "explanation", "applicability"):
            value = getattr(self, field_name).strip()
            if not value:
                raise SecurityProfileError(f"{field_name} must not be empty")
            object.__setattr__(self, field_name, value)

        try:
            requirement = (
                self.requirement
                if isinstance(self.requirement, RuleRequirement)
                else RuleRequirement(self.requirement)
            )
        except ValueError as exc:
            raise SecurityProfileError(
                f"Unsupported rule requirement {self.requirement!r}"
            ) from exc
        object.__setattr__(self, "requirement", requirement)

        try:
            severity = (
                self.severity
                if isinstance(self.severity, RuleSeverity)
                else RuleSeverity(self.severity)
            )
        except ValueError as exc:
            raise SecurityProfileError(
                f"Unsupported rule severity {self.severity!r}"
            ) from exc
        object.__setattr__(self, "severity", severity)

        if self.capability_id is not None:
            capability = self.capability_id.strip()
            if not capability:
                raise SecurityProfileError("capability_id must not be empty when supplied")
            object.__setattr__(self, "capability_id", capability)


@dataclass(frozen=True, slots=True)
class SecurityProfileDefinition:
    profile: SecurityProfile
    version: str
    description: str
    rules: tuple[SecurityRuleDefinition, ...]
    schema_version: int = SECURITY_PROFILE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SECURITY_PROFILE_SCHEMA_VERSION:
            raise SecurityProfileError(
                f"Unsupported security profile schema version {self.schema_version}"
            )
        if not self.version.strip():
            raise SecurityProfileError("security profile version must not be empty")
        if not self.description.strip():
            raise SecurityProfileError("security profile description must not be empty")
        if not self.rules:
            raise SecurityProfileError("security profile must contain at least one rule")
        ids = [rule.rule_id for rule in self.rules]
        if len(ids) != len(set(ids)):
            raise SecurityProfileError(f"duplicate rule IDs in profile {self.profile.value}")


@dataclass(frozen=True, slots=True)
class ExpandedSecurityRule:
    rule_id: str
    intent: str
    requirement: str
    severity: str
    risk_class: str
    capability_id: str | None
    capability_state: str
    explanation: str
    applicability: str
    status: str


@dataclass(frozen=True, slots=True)
class SecurityExpansionResult:
    definition: SecurityProfileDefinition
    rules: tuple[ExpandedSecurityRule, ...]
    issues: tuple[ValidationIssue, ...] = field(default_factory=tuple)

    @property
    def blocking(self) -> tuple[ValidationIssue, ...]:
        return tuple(
            issue
            for issue in self.issues
            if issue.severity in {ValidationSeverity.ERROR, ValidationSeverity.BLOCKED}
        )

    @property
    def valid(self) -> bool:
        return not self.blocking


RULE_SSH = SecurityRuleDefinition(
    rule_id="management.ssh",
    intent="Use SSH for command-line management.",
    requirement=RuleRequirement.REQUIRED,
    severity=RuleSeverity.HIGH,
    risk_class="W2",
    capability_id="ssh_management",
    explanation="Encrypted remote administration should use SSH rather than insecure plaintext management protocols.",
)

RULE_HTTPS = SecurityRuleDefinition(
    rule_id="management.https",
    intent="Use HTTPS for browser-based switch management when browser management is required.",
    requirement=RuleRequirement.RECOMMENDED,
    severity=RuleSeverity.MEDIUM,
    risk_class="W2",
    capability_id="https_management",
    explanation="Browser administration should use an encrypted management channel.",
    applicability="when browser-based administration is used",
)

RULE_MGMT_ACL = SecurityRuleDefinition(
    rule_id="management.restrict_sources",
    intent="Restrict switch administration to declared management source networks.",
    requirement=RuleRequirement.RECOMMENDED,
    severity=RuleSeverity.CRITICAL,
    risk_class="W2",
    capability_id="management_acl",
    explanation="Limiting management-plane sources reduces exposure but can lock out administrators if applied incorrectly.",
    applicability="when trusted management source networks are known",
)

RULE_REMOTE_SYSLOG = SecurityRuleDefinition(
    rule_id="logging.remote_syslog",
    intent="Send operational/security logs to a remote syslog destination.",
    requirement=RuleRequirement.RECOMMENDED,
    severity=RuleSeverity.MEDIUM,
    risk_class="W1",
    capability_id="remote_syslog",
    explanation="Remote logging preserves evidence beyond the switch's volatile/local log retention.",
    applicability="when a syslog collector is available",
)

RULE_SNMPV3 = SecurityRuleDefinition(
    rule_id="monitoring.snmpv3",
    intent="Prefer SNMPv3 for authenticated/encrypted monitoring.",
    requirement=RuleRequirement.RECOMMENDED,
    severity=RuleSeverity.MEDIUM,
    risk_class="W1",
    capability_id="snmpv3",
    explanation="SNMPv3 provides stronger management-plane protection than community-string based SNMP versions.",
    applicability="when SNMP monitoring is used",
)

RULE_IPV4_ACL = SecurityRuleDefinition(
    rule_id="segmentation.ipv4_acl",
    intent="Use explicit IPv4 ACL policy for inter-segment restrictions where required by the design.",
    requirement=RuleRequirement.CONDITIONAL,
    severity=RuleSeverity.HIGH,
    risk_class="W2",
    capability_id="ipv4_acl",
    explanation="Segmentation policy must be explicit and capability-validated rather than inferred from VLAN creation alone.",
    applicability="when the normalized segmentation intent requires L3 filtering on this switch",
)

RULE_DISABLE_TELNET_POLICY = SecurityRuleDefinition(
    rule_id="management.disable_telnet_policy",
    intent="Do not expose Telnet management in production profiles.",
    requirement=RuleRequirement.REQUIRED,
    severity=RuleSeverity.HIGH,
    risk_class="W2",
    capability_id=None,
    explanation="This is a policy requirement only until exact enable/disable capability and syntax are mapped into the device profile.",
)

RULE_DISABLE_HTTP_POLICY = SecurityRuleDefinition(
    rule_id="management.disable_http_when_safe_policy",
    intent="Disable plaintext HTTP management when HTTPS is proven usable and recovery/lockout checks pass.",
    requirement=RuleRequirement.RECOMMENDED,
    severity=RuleSeverity.MEDIUM,
    risk_class="W2",
    capability_id=None,
    explanation="This remains policy-only until exact HTTP service control is mapped and safe management-path transition is proven.",
    applicability="when HTTPS is proven and plaintext HTTP is not operationally required",
)


def _rule_with_requirement(
    rule: SecurityRuleDefinition,
    requirement: RuleRequirement,
) -> SecurityRuleDefinition:
    return SecurityRuleDefinition(
        rule_id=rule.rule_id,
        intent=rule.intent,
        requirement=requirement,
        severity=rule.severity,
        risk_class=rule.risk_class,
        capability_id=rule.capability_id,
        explanation=rule.explanation,
        applicability=rule.applicability,
    )


SECURITY_PROFILE_REGISTRY: dict[SecurityProfile, SecurityProfileDefinition] = {
    SecurityProfile.LAB: SecurityProfileDefinition(
        profile=SecurityProfile.LAB,
        version="1.0.0",
        description="Development/lab baseline with visible security guidance but fewer hard policy expectations.",
        rules=(
            _rule_with_requirement(RULE_SSH, RuleRequirement.RECOMMENDED),
            _rule_with_requirement(RULE_REMOTE_SYSLOG, RuleRequirement.CONDITIONAL),
        ),
    ),
    SecurityProfile.BASIC: SecurityProfileDefinition(
        profile=SecurityProfile.BASIC,
        version="1.0.0",
        description="Minimum practical baseline for a small trusted business environment.",
        rules=(
            RULE_SSH,
            RULE_HTTPS,
            RULE_MGMT_ACL,
            RULE_REMOTE_SYSLOG,
            RULE_DISABLE_TELNET_POLICY,
        ),
    ),
    SecurityProfile.BUSINESS_STANDARD: SecurityProfileDefinition(
        profile=SecurityProfile.BUSINESS_STANDARD,
        version="1.0.0",
        description="Default production-oriented baseline emphasizing secure management, retained logs, and explicit segmentation.",
        rules=(
            RULE_SSH,
            _rule_with_requirement(RULE_HTTPS, RuleRequirement.REQUIRED),
            _rule_with_requirement(RULE_MGMT_ACL, RuleRequirement.REQUIRED),
            _rule_with_requirement(RULE_REMOTE_SYSLOG, RuleRequirement.REQUIRED),
            RULE_SNMPV3,
            RULE_IPV4_ACL,
            RULE_DISABLE_TELNET_POLICY,
            RULE_DISABLE_HTTP_POLICY,
        ),
    ),
    SecurityProfile.STRICT: SecurityProfileDefinition(
        profile=SecurityProfile.STRICT,
        version="1.0.0",
        description="Restrictive baseline requiring stronger management and monitoring controls where applicable.",
        rules=(
            RULE_SSH,
            _rule_with_requirement(RULE_HTTPS, RuleRequirement.REQUIRED),
            _rule_with_requirement(RULE_MGMT_ACL, RuleRequirement.REQUIRED),
            _rule_with_requirement(RULE_REMOTE_SYSLOG, RuleRequirement.REQUIRED),
            _rule_with_requirement(RULE_SNMPV3, RuleRequirement.REQUIRED),
            RULE_IPV4_ACL,
            RULE_DISABLE_TELNET_POLICY,
            _rule_with_requirement(RULE_DISABLE_HTTP_POLICY, RuleRequirement.REQUIRED),
        ),
    ),
}


def list_security_profiles() -> tuple[SecurityProfileDefinition, ...]:
    return tuple(
        SECURITY_PROFILE_REGISTRY[profile]
        for profile in (
            SecurityProfile.LAB,
            SecurityProfile.BASIC,
            SecurityProfile.BUSINESS_STANDARD,
            SecurityProfile.STRICT,
        )
    )


def get_security_profile(
    profile: SecurityProfile | str,
) -> SecurityProfileDefinition:
    try:
        normalized = profile if isinstance(profile, SecurityProfile) else SecurityProfile(profile)
    except ValueError as exc:
        raise SecurityProfileError(f"Unknown security profile {profile!r}") from exc
    if normalized is SecurityProfile.CUSTOM:
        raise SecurityProfileError("CUSTOM does not have a built-in profile definition")
    return SECURITY_PROFILE_REGISTRY[normalized]


def _issue_severity_for_missing_capability(
    requirement: RuleRequirement,
    *,
    require_live_proof: bool,
) -> ValidationSeverity:
    if require_live_proof or requirement is RuleRequirement.REQUIRED:
        return ValidationSeverity.BLOCKED
    return ValidationSeverity.WARNING


def expand_security_profile(
    profile: SecurityProfile | str,
    *,
    device_profile: DeviceProfile | None = None,
    require_live_proof: bool = False,
) -> SecurityExpansionResult:
    """Expand a security profile into explainable rules and capability evidence.

    Offline design mode (`require_live_proof=False`) allows documented-but-not-observed
    capabilities with warnings. Future write precheck mode requires live proof and blocks
    any mapped rule whose capability is not ``documented_and_observed``.

    Policy-only rules with no mapped capability never create commands. They remain explicit
    unmapped policy until the exact device capability registry/provider supports them.
    """
    definition = get_security_profile(profile)
    feature_states = device_profile.feature_states if device_profile is not None else {}

    expanded: list[ExpandedSecurityRule] = []
    issues: list[ValidationIssue] = []

    for rule in definition.rules:
        capability_state = "not_checked"
        status = "policy_only"

        if rule.capability_id is None:
            capability_state = "policy_only_unmapped"
            status = "unmapped"
            issues.append(
                ValidationIssue(
                    code="SECURITY_RULE_PROVIDER_MAPPING_PENDING",
                    severity=(
                        ValidationSeverity.BLOCKED
                        if require_live_proof and rule.requirement is RuleRequirement.REQUIRED
                        else ValidationSeverity.WARNING
                    ),
                    message=(
                        f"Security rule {rule.rule_id!r} has no exact provider capability mapping yet."
                    ),
                    remediation=(
                        "Keep the rule as policy guidance only; do not generate device commands until exact capability/syntax is mapped."
                    ),
                )
            )
        elif device_profile is None:
            capability_state = "profile_not_supplied"
            status = "not_checked"
            issues.append(
                ValidationIssue(
                    code="SECURITY_RULE_CAPABILITY_NOT_CHECKED",
                    severity=ValidationSeverity.WARNING,
                    message=(
                        f"Security rule {rule.rule_id!r} requires capability "
                        f"{rule.capability_id!r}, but no device profile was supplied."
                    ),
                    remediation="Select an exact device/firmware profile before provider planning.",
                )
            )
        else:
            state = feature_states.get(rule.capability_id)
            if state is None:
                capability_state = "absent_from_profile"
                status = "blocked" if rule.requirement is RuleRequirement.REQUIRED else "unproven"
                issues.append(
                    ValidationIssue(
                        code="SECURITY_RULE_CAPABILITY_UNKNOWN",
                        severity=_issue_severity_for_missing_capability(
                            rule.requirement,
                            require_live_proof=require_live_proof,
                        ),
                        message=(
                            f"Security rule {rule.rule_id!r} depends on capability "
                            f"{rule.capability_id!r}, which is absent from profile {device_profile.profile_id}."
                        ),
                        remediation="Map and verify the exact capability before planning this rule.",
                    )
                )
            else:
                capability_state = state.value
                if state is CapabilityState.DOCUMENTED_AND_OBSERVED:
                    status = "proven"
                elif state is CapabilityState.NOT_APPLICABLE_OR_UNSUPPORTED:
                    status = "unsupported"
                    issues.append(
                        ValidationIssue(
                            code="SECURITY_RULE_UNSUPPORTED",
                            severity=_issue_severity_for_missing_capability(
                                rule.requirement,
                                require_live_proof=require_live_proof,
                            ),
                            message=(
                                f"Security rule {rule.rule_id!r} depends on unsupported capability "
                                f"{rule.capability_id!r}."
                            ),
                            remediation="Do not plan this rule on the selected target; choose another control or device.",
                        )
                    )
                else:
                    status = "documented_unproven"
                    issues.append(
                        ValidationIssue(
                            code="SECURITY_RULE_CAPABILITY_UNPROVEN",
                            severity=(
                                ValidationSeverity.BLOCKED
                                if require_live_proof
                                else ValidationSeverity.WARNING
                            ),
                            message=(
                                f"Security rule {rule.rule_id!r} depends on {rule.capability_id!r} "
                                f"in state {state.value!r}."
                            ),
                            remediation=(
                                "Offline design may retain the rule as an assumption, but live write planning must wait for exact proof."
                            ),
                        )
                    )

        expanded.append(
            ExpandedSecurityRule(
                rule_id=rule.rule_id,
                intent=rule.intent,
                requirement=rule.requirement.value,
                severity=rule.severity.value,
                risk_class=rule.risk_class,
                capability_id=rule.capability_id,
                capability_state=capability_state,
                explanation=rule.explanation,
                applicability=rule.applicability,
                status=status,
            )
        )

    return SecurityExpansionResult(
        definition=definition,
        rules=tuple(expanded),
        issues=tuple(issues),
    )
