"""Repository for persistent memory operations."""

import json
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy.orm import Session
from sensei.memory.database import get_db_session
from sensei.memory.models import (
    SessionRecord,
    TargetScopeRecord,
    PlanRecord,
    PlanStepRecord,
    ToolExecutionRecord,
    FindingRecord,
    ReportRecord,
    AuditLogRecord,
)


class SenseiRepository:
    """Provides abstracted persistence operations."""

    def __init__(self, db: Optional[Session] = None):
        self._db = db

    def _get_session(self) -> Session:
        return self._db if self._db is not None else get_db_session()

    # Session Management
    def create_session(self, name: str, mode: str = "COPILOT", session_id: Optional[str] = None) -> SessionRecord:
        db = self._get_session()
        record = SessionRecord(
            name=name,
            mode=mode,
            status="active"
        )
        if session_id:
            record.id = session_id
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    def get_session(self, session_id: str) -> Optional[SessionRecord]:
        db = self._get_session()
        return db.query(SessionRecord).filter(SessionRecord.id == session_id).first()

    def list_sessions(self, limit: int = 20) -> List[SessionRecord]:
        db = self._get_session()
        return db.query(SessionRecord).order_by(SessionRecord.updated_at.desc()).limit(limit).all()

    def update_session_usage(self, session_id: str, tokens_delta: int = 0, cost_delta: float = 0.0) -> None:
        db = self._get_session()
        record = db.query(SessionRecord).filter(SessionRecord.id == session_id).first()
        if record:
            record.token_usage = (record.token_usage or 0) + tokens_delta
            record.cost_usage = (record.cost_usage or 0.0) + cost_delta
            record.updated_at = datetime.now(timezone.utc)
            db.commit()

    # Target Scope Persistence
    def add_target_scope(
        self, session_id: str, target: str, is_authorized: bool = False, authorized_by: str = "user", notes: str = ""
    ) -> TargetScopeRecord:
        db = self._get_session()
        record = TargetScopeRecord(
            session_id=session_id,
            target=target,
            is_authorized=is_authorized,
            authorized_by=authorized_by,
            notes=notes,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    def get_scopes(self, session_id: str) -> List[TargetScopeRecord]:
        db = self._get_session()
        return db.query(TargetScopeRecord).filter(TargetScopeRecord.session_id == session_id).all()

    # Plan Persistence
    def save_plan(self, session_id: str, objective: str, steps: List[dict], plan_id: Optional[str] = None) -> PlanRecord:
        db = self._get_session()
        plan = PlanRecord(
            session_id=session_id,
            objective=objective,
            status="in_progress",
        )
        if plan_id:
            plan.id = plan_id
        db.add(plan)
        db.flush()

        for idx, step_dict in enumerate(steps):
            step_record = PlanStepRecord(
                plan_id=plan.id,
                step_index=idx,
                description=step_dict.get("description", ""),
                tool_name=step_dict.get("tool_name", ""),
                risk_level=step_dict.get("risk_level", "LOW"),
                status=step_dict.get("status", "pending"),
                approval_status=step_dict.get("approval_status", "auto_approved"),
                tool_input=json.dumps(step_dict.get("tool_input", {})),
                result_summary=step_dict.get("result_summary", ""),
            )
            db.add(step_record)

        db.commit()
        db.refresh(plan)
        return plan

    # Tool Execution Persistence
    def record_tool_execution(
        self,
        session_id: str,
        tool_name: str,
        tool_category: str,
        input_data: dict,
        output_data: str,
        is_truncated: bool,
        duration_seconds: float,
        exit_code: int = 0,
        status: str = "success",
    ) -> ToolExecutionRecord:
        db = self._get_session()
        record = ToolExecutionRecord(
            session_id=session_id,
            tool_name=tool_name,
            tool_category=tool_category,
            input_data=json.dumps(input_data),
            output_data=output_data,
            is_truncated=is_truncated,
            duration_seconds=duration_seconds,
            exit_code=exit_code,
            status=status,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    # Finding Persistence
    def save_finding(
        self,
        session_id: str,
        finding_id: str,
        title: str,
        description: str,
        severity: str,
        affected_asset: str,
        confidence: str = "CONFIRMED",
        evidence: str = "",
        reproduction: str = "",
        impact: str = "",
        remediation: str = "",
        references: Optional[List[str]] = None,
        validation_status: str = "CONFIRMED",
    ) -> FindingRecord:
        db = self._get_session()
        record = FindingRecord(
            session_id=session_id,
            finding_id=finding_id,
            title=title,
            description=description,
            severity=severity,
            affected_asset=affected_asset,
            confidence=confidence,
            evidence=evidence,
            reproduction=reproduction,
            impact=impact,
            remediation=remediation,
            references=json.dumps(references or []),
            validation_status=validation_status,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    def get_findings(self, session_id: str) -> List[FindingRecord]:
        db = self._get_session()
        return db.query(FindingRecord).filter(FindingRecord.session_id == session_id).all()

    # Report Persistence
    def save_report(
        self, session_id: str, format_name: str, title: str, content: str, file_path: str = ""
    ) -> ReportRecord:
        db = self._get_session()
        record = ReportRecord(
            session_id=session_id,
            format=format_name,
            title=title,
            content=content,
            file_path=file_path,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    def get_reports(self, session_id: str) -> List[ReportRecord]:
        db = self._get_session()
        return db.query(ReportRecord).filter(ReportRecord.session_id == session_id).all()

    # Audit Persistence
    def save_audit(self, session_id: str, action: str, actor: str, status: str, details: dict) -> AuditLogRecord:
        db = self._get_session()
        record = AuditLogRecord(
            session_id=session_id,
            action=action,
            actor=actor,
            status=status,
            details=json.dumps(details),
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record
