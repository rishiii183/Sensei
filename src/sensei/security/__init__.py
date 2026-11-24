"""Sensei Security, Permissions, and Scope Subsystem."""

from sensei.security.scope import TargetScope, ScopeRegistry, get_scope_registry
from sensei.security.permissions import (
    ActionRiskLevel,
    PermissionDecision,
    evaluate_permission,
    RESTRICTED_OPERATION_PATTERNS,
)
from sensei.security.approvals import (
    ApprovalRequest,
    ApprovalManager,
    get_approval_manager,
)
from sensei.security.audit import AuditEvent, SecurityAuditLogger, get_audit_logger
from sensei.security.sanitizer import (
    sanitize_untrusted_content,
    wrap_untrusted_data,
    truncate_tool_output,
)

__all__ = [
    "TargetScope",
    "ScopeRegistry",
    "get_scope_registry",
    "ActionRiskLevel",
    "PermissionDecision",
    "evaluate_permission",
    "RESTRICTED_OPERATION_PATTERNS",
    "ApprovalRequest",
    "ApprovalManager",
    "get_approval_manager",
    "AuditEvent",
    "SecurityAuditLogger",
    "get_audit_logger",
    "sanitize_untrusted_content",
    "wrap_untrusted_data",
    "truncate_tool_output",
]
