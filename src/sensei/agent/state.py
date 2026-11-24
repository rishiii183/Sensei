"""LangGraph orchestration state and structured planning models."""

from typing import Any, Dict, List, Optional, TypedDict
from pydantic import BaseModel, Field
from sensei.tools.schemas import ToolFinding, ToolOutput
from sensei.reporting.models import Finding, SecurityReport
from sensei.agent.llm import CostTracker


class PlanStep(BaseModel):
    """Single step in an autonomous security assessment plan."""

    step_index: int
    specialist: str = "web_security"  # recon, web_security, api_security, ai_security
    description: str
    tool_name: str
    risk_level: str = "LOW"
    tool_input: Dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""
    status: str = "pending"  # pending, approved, running, completed, skipped, failed, blocked
    approval_status: str = "pending"  # auto_approved, approved, denied, waiting
    result_summary: str = ""


class AssessmentPlan(BaseModel):
    """Structured security assessment execution plan."""

    plan_id: str
    objective: str
    target: str
    selected_skills: List[str] = Field(default_factory=list)
    steps: List[PlanStep] = Field(default_factory=list)
    reasoning_summary: str = ""


class SenseiState(TypedDict, total=False):
    """Central state passed across LangGraph nodes."""

    session_id: str
    instruction: str
    target: str
    target_authorized: bool
    scope_reason: str
    operating_mode: str
    plan: Optional[AssessmentPlan]
    current_step_index: int
    tool_outputs: List[ToolOutput]
    raw_findings: List[ToolFinding]
    validated_findings: List[Finding]
    mentor_guidance: str
    report: Optional[SecurityReport]
    execution_logs: List[str]
    reasoning_summaries: List[str]
    pending_approvals: List[Dict[str, Any]]
    budget_exceeded: bool
    cost_tracker: CostTracker
    error: Optional[str]
