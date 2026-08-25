"""Offline risk and management-impact analysis for semantic change plans.

This module does not decide that a plan is safe to apply. It summarizes risk and identifies
management-path dependencies that a future P6 lockout engine must prove before execution.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import NetworkIntent
from .planner import ChangePlan, OperationReadiness, OperationType


RISK_ORDER = {"R0": 0, "R1": 1, "R2": 2, "W1": 3, "W2": 4, "D": 5}


@dataclass(frozen=True, slots=True)
class RiskSummary:
    counts: tuple[tuple[str, int], ...]
    highest_risk: str | None
    connectivity_impacting_operation_ids: tuple[str, ...]
    destructive_operation_ids: tuple[str, ...]
    future_safety_gate_required: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "counts": {risk: count for risk, count in self.counts},
            "highest_risk": self.highest_risk,
            "connectivity_impacting_operation_ids": list(
                self.connectivity_impacting_operation_ids
            ),
            "destructive_operation_ids": list(self.destructive_operation_ids),
            "future_safety_gate_required": self.future_safety_gate_required,
        }


@dataclass(frozen=True, slots=True)
class ManagementImpactSummary:
    management_vlan_id: int | None
    affected_operation_ids: tuple[str, ...]
    affected_targets: tuple[str, ...]
    blocked_operation_ids: tuple[str, ...]
    status: str
    lockout_analysis_complete: bool = False
    safe_to_apply: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "management_vlan_id": self.management_vlan_id,
            "affected_operation_ids": list(self.affected_operation_ids),
            "affected_targets": list(self.affected_targets),
            "blocked_operation_ids": list(self.blocked_operation_ids),
            "status": self.status,
            "lockout_analysis_complete": self.lockout_analysis_complete,
            "safe_to_apply": self.safe_to_apply,
        }


@dataclass(frozen=True, slots=True)
class PlanAnalysis:
    risk: RiskSummary
    management_impact: ManagementImpactSummary

    def as_dict(self) -> dict[str, object]:
        return {
            "risk_summary": self.risk.as_dict(),
            "management_impact": self.management_impact.as_dict(),
        }

    def render_text(self) -> str:
        counts = ", ".join(f"{risk}={count}" for risk, count in self.risk.counts) or "none"
        lines = [
            "PLAN RISK SUMMARY",
            "=================",
            f"Risk counts: {counts}",
            f"Highest risk: {self.risk.highest_risk or 'NONE'}",
            (
                "Future safety gate required: YES"
                if self.risk.future_safety_gate_required
                else "Future safety gate required: NO"
            ),
            "",
            "MANAGEMENT IMPACT",
            "=================",
            f"Management VLAN: {self.management_impact.management_vlan_id or 'not-declared'}",
            f"Status: {self.management_impact.status}",
            "Lockout analysis complete: NO",
            "Safe to apply: NO",
        ]
        if self.management_impact.affected_operation_ids:
            lines.append(
                "Affected operations: "
                + ", ".join(self.management_impact.affected_operation_ids)
            )
            lines.append(
                "Affected targets: " + ", ".join(self.management_impact.affected_targets)
            )
        else:
            lines.append("No direct management-path change identified by the P4 semantic plan.")
        if self.management_impact.blocked_operation_ids:
            lines.append(
                "Currently blocked management operations: "
                + ", ".join(self.management_impact.blocked_operation_ids)
            )
        lines.append(
            "A future P6 lockout engine must independently prove management reachability/recovery before any apply."
        )
        return "\n".join(lines)


def _risk_summary(plan: ChangePlan) -> RiskSummary:
    counts: dict[str, int] = {}
    connectivity: list[str] = []
    destructive: list[str] = []
    for operation in plan.operations:
        counts[operation.risk_class] = counts.get(operation.risk_class, 0) + 1
        if operation.risk_class in {"W2", "D"}:
            connectivity.append(operation.operation_id)
        if operation.risk_class == "D" or operation.destructive:
            destructive.append(operation.operation_id)

    ordered_counts = tuple(
        (risk, counts[risk])
        for risk in sorted(counts, key=lambda value: (RISK_ORDER.get(value, 99), value))
    )
    highest = (
        max(counts, key=lambda value: RISK_ORDER.get(value, 99))
        if counts
        else None
    )
    return RiskSummary(
        counts=ordered_counts,
        highest_risk=highest,
        connectivity_impacting_operation_ids=tuple(connectivity),
        destructive_operation_ids=tuple(destructive),
        future_safety_gate_required=bool(connectivity or destructive),
    )


def _operation_affects_management(operation, intent: NetworkIntent, management_vlan_id: int | None) -> bool:
    if operation.operation_type is OperationType.SET_MANAGEMENT_POLICY:
        return True
    if operation.operation_type is OperationType.APPLY_SECURITY_POLICY_RULE:
        return str(operation.desired.get("rule_id", "")).startswith("management.")
    if management_vlan_id is None:
        return False
    if operation.target in {
        f"vlan:{management_vlan_id}",
        f"vlan-l3:{management_vlan_id}",
    }:
        return True
    if operation.operation_type is OperationType.ASSIGN_ACCESS_PORT:
        return operation.desired.get("access_vlan") == management_vlan_id
    if operation.operation_type in {
        OperationType.CONFIGURE_TRUNK,
        OperationType.SET_ALLOWED_VLANS,
    }:
        allowed = operation.desired.get("allowed_vlans", [])
        return management_vlan_id in allowed
    return False


def _management_impact(plan: ChangePlan, intent: NetworkIntent) -> ManagementImpactSummary:
    management_vlan_id = intent.management.vlan_id if intent.management is not None else None
    affected = [
        operation
        for operation in plan.operations
        if _operation_affects_management(operation, intent, management_vlan_id)
    ]
    blocked = [
        operation.operation_id
        for operation in affected
        if operation.readiness is not OperationReadiness.READY
    ]

    if not affected:
        status = "NO_DIRECT_MANAGEMENT_CHANGE_IDENTIFIED"
    elif blocked:
        status = "REVIEW_REQUIRED_AND_CURRENTLY_BLOCKED"
    else:
        status = "REVIEW_REQUIRED"

    return ManagementImpactSummary(
        management_vlan_id=management_vlan_id,
        affected_operation_ids=tuple(operation.operation_id for operation in affected),
        affected_targets=tuple(sorted({operation.target for operation in affected})),
        blocked_operation_ids=tuple(blocked),
        status=status,
    )


def analyze_change_plan(plan: ChangePlan, intent: NetworkIntent) -> PlanAnalysis:
    return PlanAnalysis(
        risk=_risk_summary(plan),
        management_impact=_management_impact(plan, intent),
    )
