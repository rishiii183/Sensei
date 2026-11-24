"""Execution runner enforcing scope, permissions, timeouts, rate limits, and audit logs."""

from typing import Any, Dict, Optional
from sensei.config import get_config
from sensei.tools.registry import get_tool_registry
from sensei.tools.schemas import ToolOutput
from sensei.security.scope import get_scope_registry
from sensei.security.permissions import ActionRiskLevel, evaluate_permission
from sensei.security.audit import get_audit_logger
from sensei.security.approvals import get_approval_manager, ApprovalRequest
from sensei.memory.repository import SenseiRepository


class ToolExecutionRunner:
    """Coordinates and executes security tools safely within strict security boundaries."""

    def __init__(self, repo: Optional[SenseiRepository] = None):
        self.repo = repo or SenseiRepository()
        self.scope_registry = get_scope_registry()
        self.audit_logger = get_audit_logger()
        self.approval_manager = get_approval_manager()

    def run_tool(
        self,
        tool_name: str,
        input_data: Dict[str, Any],
        session_id: str,
        target: Optional[str] = None,
        timeout: Optional[int] = None,
        force_approved: bool = False,
    ) -> ToolOutput:
        """
        Safely execute a tool with end-to-end security gating:
        1. Registry lookup
        2. Scope verification
        3. Permission risk evaluation
        4. Approval resolution
        5. Execution with rate limiting and timeout
        6. Audit & SQLite logging
        """
        config = get_config()
        effective_target = target or str(input_data.get("target") or input_data.get("source") or "")

        # 1. Lookup Tool
        tool = get_tool_registry().get(tool_name)
        if not tool:
            return ToolOutput(
                tool_name=tool_name,
                success=False,
                exit_code=-1,
                error_message=f"Tool '{tool_name}' not found in registry.",
            )

        # 2. Scope verification for network/web tools
        if "http" in tool_name or tool_name in ("nuclei", "nmap", "http_audit"):
            in_scope, scope_reason = self.scope_registry.is_in_scope(effective_target)
            if not in_scope:
                self.audit_logger.log(
                    session_id=session_id,
                    action=f"execute_tool:{tool_name}",
                    actor="agent",
                    status="BLOCKED_SCOPE",
                    target=effective_target,
                    details={"reason": scope_reason},
                )
                return ToolOutput(
                    tool_name=tool_name,
                    success=False,
                    exit_code=-10,
                    error_message=scope_reason,
                )
            target_authorized = True
        else:
            target_authorized = True

        # 3. Permission and Risk Tier Evaluation
        risk_level = ActionRiskLevel(tool.info.required_permissions.upper())
        decision = evaluate_permission(
            action_name=tool_name,
            risk_level=risk_level,
            mode=config.mode,
            is_target_authorized=target_authorized,
            description=tool.info.description,
        )

        if not decision.allowed:
            self.audit_logger.log(
                session_id=session_id,
                action=f"execute_tool:{tool_name}",
                actor="agent",
                status="BLOCKED_PERMISSION",
                target=effective_target,
                details={"reason": decision.reason},
            )
            return ToolOutput(
                tool_name=tool_name,
                success=False,
                exit_code=-11,
                error_message=f"Permission Denied: {decision.reason}",
            )

        # 4. Approval Check
        if decision.requires_approval and not force_approved:
            req_id = f"{session_id}-{tool_name}"
            req = ApprovalRequest(
                request_id=req_id,
                action_name=f"Run {tool.info.display_name}",
                target=effective_target,
                risk_level=risk_level.value,
                description=tool.info.description,
                tool_name=tool_name,
                parameters=input_data,
            )
            approved = self.approval_manager.request_approval(req)
            if not approved:
                self.audit_logger.log(
                    session_id=session_id,
                    action=f"execute_tool:{tool_name}",
                    actor="user",
                    status="WAITING_APPROVAL",
                    target=effective_target,
                    details={"request_id": req_id},
                )
                return ToolOutput(
                    tool_name=tool_name,
                    success=False,
                    exit_code=-12,
                    error_message=f"Action '{tool_name}' requires approval. Request ID: {req_id}. Use '/approve {req_id}' to proceed.",
                )

        # 5. Execute Tool via Adapter
        self.audit_logger.log(
            session_id=session_id,
            action=f"execute_tool:{tool_name}",
            actor="agent",
            status="STARTED",
            target=effective_target,
            details={"input": input_data},
        )

        output = tool.execute(input_data, timeout=timeout)

        # 6. Audit & SQLite Persistence
        status_str = "SUCCESS" if output.success else "FAILED"
        self.audit_logger.log(
            session_id=session_id,
            action=f"execute_tool:{tool_name}",
            actor="agent",
            status=status_str,
            target=effective_target,
            details={
                "exit_code": output.exit_code,
                "findings_count": len(output.findings),
                "duration_seconds": output.duration_seconds,
            },
        )

        try:
            self.repo.record_tool_execution(
                session_id=session_id,
                tool_name=tool_name,
                tool_category=tool.info.category.value,
                input_data=input_data,
                output_data=output.raw_output,
                is_truncated=output.is_truncated,
                duration_seconds=output.duration_seconds,
                exit_code=output.exit_code,
                status=status_str.lower(),
            )
        except Exception:
            pass

        return output
