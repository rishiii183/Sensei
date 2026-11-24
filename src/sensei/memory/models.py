"""SQLAlchemy ORM models for Sensei persistence."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Boolean, Text, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from sensei.memory.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SessionRecord(Base):
    """Assessment session history."""
    __tablename__ = "sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    mode = Column(String(32), default="COPILOT")
    status = Column(String(32), default="active")  # active, completed, paused
    token_usage = Column(Integer, default=0)
    cost_usage = Column(Float, default=0.0)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    targets = relationship("TargetScopeRecord", back_populates="session", cascade="all, delete-orphan")
    plans = relationship("PlanRecord", back_populates="session", cascade="all, delete-orphan")
    tool_executions = relationship("ToolExecutionRecord", back_populates="session", cascade="all, delete-orphan")
    findings = relationship("FindingRecord", back_populates="session", cascade="all, delete-orphan")
    reports = relationship("ReportRecord", back_populates="session", cascade="all, delete-orphan")


class TargetScopeRecord(Base):
    """Registered target scopes for a session."""
    __tablename__ = "target_scopes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), ForeignKey("sessions.id"), nullable=False)
    target = Column(String(512), nullable=False)
    is_authorized = Column(Boolean, default=False)
    authorized_by = Column(String(128), default="user")
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=utc_now)

    session = relationship("SessionRecord", back_populates="targets")


class PlanRecord(Base):
    """Generated assessment plans."""
    __tablename__ = "plans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String(36), ForeignKey("sessions.id"), nullable=False)
    objective = Column(Text, nullable=False)
    status = Column(String(32), default="in_progress")  # planned, in_progress, completed, failed
    created_at = Column(DateTime, default=utc_now)

    session = relationship("SessionRecord", back_populates="plans")
    steps = relationship("PlanStepRecord", back_populates="plan", cascade="all, delete-orphan")


class PlanStepRecord(Base):
    """Steps in an assessment plan."""
    __tablename__ = "plan_steps"

    id = Column(Integer, primary_key=True, autoincrement=True)
    plan_id = Column(String(36), ForeignKey("plans.id"), nullable=False)
    step_index = Column(Integer, nullable=False)
    description = Column(Text, nullable=False)
    tool_name = Column(String(64), nullable=False)
    risk_level = Column(String(32), default="LOW")
    status = Column(String(32), default="pending")  # pending, approved, running, completed, skipped, failed
    approval_status = Column(String(32), default="auto_approved")
    tool_input = Column(Text, default="{}")
    result_summary = Column(Text, default="")

    plan = relationship("PlanRecord", back_populates="steps")


class ToolExecutionRecord(Base):
    """History of all tool executions."""
    __tablename__ = "tool_executions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), ForeignKey("sessions.id"), nullable=False)
    tool_name = Column(String(64), nullable=False)
    tool_category = Column(String(64), default="")
    input_data = Column(Text, default="{}")
    output_data = Column(Text, default="")
    is_truncated = Column(Boolean, default=False)
    duration_seconds = Column(Float, default=0.0)
    exit_code = Column(Integer, default=0)
    status = Column(String(32), default="success")
    executed_at = Column(DateTime, default=utc_now)

    session = relationship("SessionRecord", back_populates="tool_executions")


class FindingRecord(Base):
    """Validated or potential security findings."""
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), ForeignKey("sessions.id"), nullable=False)
    finding_id = Column(String(64), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(32), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    confidence = Column(String(32), default="CONFIRMED")  # CONFIRMED, HIGH, MEDIUM, LOW
    affected_asset = Column(String(512), nullable=False)
    evidence = Column(Text, default="")
    reproduction = Column(Text, default="")
    impact = Column(Text, default="")
    remediation = Column(Text, default="")
    references = Column(Text, default="[]")
    validation_status = Column(String(32), default="CONFIRMED")  # CONFIRMED, POTENTIAL, INFORMATIONAL
    created_at = Column(DateTime, default=utc_now)

    session = relationship("SessionRecord", back_populates="findings")


class ReportRecord(Base):
    """Generated security reports."""
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String(36), ForeignKey("sessions.id"), nullable=False)
    format = Column(String(16), nullable=False)  # markdown, json, html, terminal
    title = Column(String(255), nullable=False)
    content = Column(Text, nullable=False)
    file_path = Column(String(512), default="")
    created_at = Column(DateTime, default=utc_now)

    session = relationship("SessionRecord", back_populates="reports")


class AuditLogRecord(Base):
    """Persistent audit logs."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), nullable=False)
    action = Column(String(128), nullable=False)
    actor = Column(String(64), default="agent")
    status = Column(String(32), nullable=False)
    details = Column(Text, default="{}")
    created_at = Column(DateTime, default=utc_now)
