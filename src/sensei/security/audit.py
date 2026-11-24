"""Security audit logging system for all Sensei actions and decisions."""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

# Setup python logger
logger = logging.getLogger("sensei.audit")


class AuditEvent(BaseModel):
    """Structured record of an audited security action."""
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    session_id: str
    action: str
    actor: str = "agent"
    status: str
    target: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class SecurityAuditLogger:
    """In-memory and persistent audit logger."""

    def __init__(self) -> None:
        self._events: List[AuditEvent] = []

    def log(
        self,
        session_id: str,
        action: str,
        status: str,
        actor: str = "agent",
        target: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Record an audit event."""
        event = AuditEvent(
            session_id=session_id,
            action=action,
            actor=actor,
            status=status,
            target=target,
            details=details or {},
        )
        self._events.append(event)
        logger.info(
            f"[AUDIT] [{event.timestamp}] session={session_id} action={action} "
            f"status={status} target={target} details={json.dumps(event.details)}"
        )
        return event

    def get_session_events(self, session_id: str) -> List[AuditEvent]:
        """Fetch all events for a given session."""
        return [e for e in self._events if e.session_id == session_id]

    def get_all_events(self) -> List[AuditEvent]:
        """Fetch all recorded events."""
        return list(self._events)

    def clear(self) -> None:
        """Clear recorded events."""
        self._events.clear()


_global_audit_logger = SecurityAuditLogger()


def get_audit_logger() -> SecurityAuditLogger:
    """Return the global audit logger."""
    return _global_audit_logger
