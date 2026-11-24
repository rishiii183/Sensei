"""Permissions, risk classification, and guardrails."""

from enum import Enum
from typing import Optional
from sensei.config import OperatingMode


class ActionRiskLevel(str, Enum):
    """Risk tiers for security operations."""
    SAFE = "SAFE"                # Pure passive read, documentation, banner check
    LOW = "LOW"                  # Non-destructive template scan, header check, technology detection
    MEDIUM = "MEDIUM"            # Standard fuzzing, path enumeration, endpoint probing
    HIGH = "HIGH"                # Heavy vulnerability active probing, port sweeping
    RESTRICTED = "RESTRICTED"    # Strictly forbidden operations (always blocked)


# Category of operations that are categorically prohibited across all modes
RESTRICTED_OPERATION_PATTERNS = [
    "denial_of_service",
    "dos",
    "ddos",
    "destructive_exploit",
    "credential_dump",
    "credential_stuffing",
    "data_exfiltration",
    "persistence",
    "backdoor",
    "ransomware",
    "lateral_movement",
    "privilege_escalation_exploit",
]


class PermissionDecision:
    """Represents the outcome of a permission check."""
    def __init__(self, allowed: bool, requires_approval: bool, reason: str):
        self.allowed = allowed
        self.requires_approval = requires_approval
        self.reason = reason

    def __repr__(self) -> str:
        return f"PermissionDecision(allowed={self.allowed}, requires_approval={self.requires_approval}, reason={self.reason})"


def evaluate_permission(
    action_name: str,
    risk_level: ActionRiskLevel,
    mode: OperatingMode,
    is_target_authorized: bool,
    description: str = "",
) -> PermissionDecision:
    """
    Evaluate whether an action is permitted under the given operating mode and authorization.
    
    Rules:
    1. If target is not authorized -> BLOCKED.
    2. If risk is RESTRICTED or action matches forbidden patterns -> PERMANENTLY BLOCKED.
    3. In OBSERVE mode -> SAFE is allowed; everything else requires explicit approval.
    4. In COPILOT mode (default) -> SAFE and LOW are allowed; MEDIUM and HIGH require explicit approval.
    5. In AUTOPILOT mode -> SAFE, LOW, MEDIUM are allowed; HIGH requires explicit approval.
    """
    if not is_target_authorized:
        return PermissionDecision(
            allowed=False,
            requires_approval=False,
            reason="Target is outside authorized scope. Assessment blocked by scope guardrails."
        )

    # Check for strictly restricted operations
    action_lower = action_name.lower()
    desc_lower = description.lower()
    for forbidden in RESTRICTED_OPERATION_PATTERNS:
        if forbidden in action_lower or forbidden in desc_lower:
            return PermissionDecision(
                allowed=False,
                requires_approval=False,
                reason=f"Action '{action_name}' is classified as RESTRICTED ({forbidden}). Strictly prohibited by Sensei safety policy."
            )

    if risk_level == ActionRiskLevel.RESTRICTED:
        return PermissionDecision(
            allowed=False,
            requires_approval=False,
            reason=f"Action '{action_name}' has RESTRICTED risk level. Strictly prohibited."
        )

    # Operating Mode Rules
    if mode == OperatingMode.OBSERVE:
        if risk_level == ActionRiskLevel.SAFE:
            return PermissionDecision(allowed=True, requires_approval=False, reason="Observe mode: SAFE action permitted.")
        return PermissionDecision(
            allowed=True,
            requires_approval=True,
            reason=f"Observe mode: {risk_level.value} action '{action_name}' requires explicit manual approval."
        )

    elif mode == OperatingMode.COPILOT:
        if risk_level in (ActionRiskLevel.SAFE, ActionRiskLevel.LOW):
            return PermissionDecision(
                allowed=True,
                requires_approval=False,
                reason=f"Copilot mode: {risk_level.value} risk action permitted automatically for authorized target."
            )
        return PermissionDecision(
            allowed=True,
            requires_approval=True,
            reason=f"Copilot mode: {risk_level.value} risk action '{action_name}' requires user confirmation before execution."
        )

    elif mode == OperatingMode.AUTOPILOT:
        if risk_level in (ActionRiskLevel.SAFE, ActionRiskLevel.LOW, ActionRiskLevel.MEDIUM):
            return PermissionDecision(
                allowed=True,
                requires_approval=False,
                reason=f"Autopilot mode: {risk_level.value} risk workflow step authorized under predefined boundaries."
            )
        return PermissionDecision(
            allowed=True,
            requires_approval=True,
            reason=f"Autopilot mode: HIGH risk action '{action_name}' requires safety confirmation."
        )

    return PermissionDecision(allowed=False, requires_approval=False, reason="Unknown operating mode or policy.")
