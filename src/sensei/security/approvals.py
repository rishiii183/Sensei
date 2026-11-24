"""Interactive approval manager for human-in-the-loop permission requests."""

from typing import Dict, Optional, Callable
from pydantic import BaseModel, Field


class ApprovalRequest(BaseModel):
    """Details of an action awaiting user approval."""
    request_id: str
    action_name: str
    target: str
    risk_level: str
    description: str
    tool_name: str
    parameters: dict = Field(default_factory=dict)
    approved: Optional[bool] = None
    denial_reason: Optional[str] = None


class ApprovalManager:
    """Tracks and resolves pending approval requests."""

    def __init__(self) -> None:
        self._pending: Dict[str, ApprovalRequest] = {}
        self._history: list[ApprovalRequest] = []
        self._auto_approver: Optional[Callable[[ApprovalRequest], bool]] = None

    def set_auto_approver(self, approver: Optional[Callable[[ApprovalRequest], bool]]) -> None:
        """Set a custom hook to resolve approvals (used in tests or scripted sessions)."""
        self._auto_approver = approver

    def request_approval(self, request: ApprovalRequest) -> bool:
        """
        Register a request for approval.
        If an auto-approver is configured, it resolves immediately; otherwise queued in _pending.
        """
        if self._auto_approver is not None:
            approved = self._auto_approver(request)
            request.approved = approved
            if not approved and not request.denial_reason:
                request.denial_reason = "Denied by policy/approver"
            self._history.append(request)
            return approved

        self._pending[request.request_id] = request
        return False

    def approve(self, request_id: str) -> bool:
        """Explicitly approve a pending request."""
        if request_id in self._pending:
            req = self._pending.pop(request_id)
            req.approved = True
            self._history.append(req)
            return True
        return False

    def deny(self, request_id: str, reason: str = "User denied execution") -> bool:
        """Explicitly deny a pending request."""
        if request_id in self._pending:
            req = self._pending.pop(request_id)
            req.approved = False
            req.denial_reason = reason
            self._history.append(req)
            return True
        return False

    def get_pending(self, request_id: str) -> Optional[ApprovalRequest]:
        """Fetch pending request by ID."""
        return self._pending.get(request_id)

    def list_pending(self) -> list[ApprovalRequest]:
        """List all pending approval requests."""
        return list(self._pending.values())

    def clear(self) -> None:
        """Clear all requests."""
        self._pending.clear()
        self._history.clear()


# Global default approval manager
_global_approval_manager = ApprovalManager()


def get_approval_manager() -> ApprovalManager:
    """Return the global approval manager."""
    return _global_approval_manager
