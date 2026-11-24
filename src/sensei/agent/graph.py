"""LangGraph central orchestration graph for Sensei."""

from typing import Callable, Optional
from langgraph.graph import StateGraph, END
from sensei.agent.llm import BudgetExceededError, CostTracker, SenseiLLMClient
from sensei.agent.planner import PlanningEngine
from sensei.agent.state import PlanStep, SenseiState
from sensei.agent.verifier import ResultValidator
from sensei.agents.recon import ReconSpecialist
from sensei.agents.web_security import WebSecuritySpecialist
from sensei.agents.api_security import ApiSecuritySpecialist
from sensei.agents.ai_security import AiSecuritySpecialist
from sensei.agents.mentor import SecurityMentor
from sensei.config import OperatingMode, get_config
from sensei.execution.runner import ToolExecutionRunner
from sensei.memory.repository import SenseiRepository
from sensei.reporting.generator import ReportGenerator
from sensei.security.approvals import ApprovalRequest, get_approval_manager
from sensei.security.audit import get_audit_logger
from sensei.security.permissions import ActionRiskLevel, evaluate_permission
from sensei.security.scope import get_scope_registry


ApprovalCallback = Callable[[PlanStep, str], bool]
StatusCallback = Callable[[str], None]


def build_sensei_graph(
    runner: Optional[ToolExecutionRunner] = None,
    repo: Optional[SenseiRepository] = None,
    llm_client: Optional[SenseiLLMClient] = None,
    approval_callback: Optional[ApprovalCallback] = None,
    status_callback: Optional[StatusCallback] = None,
):
    """Compile and return the LangGraph StateGraph for Sensei orchestration."""
    repo = repo or SenseiRepository()
    runner = runner or ToolExecutionRunner(repo=repo)
    llm_client = llm_client or SenseiLLMClient()
    planner_engine = PlanningEngine(llm_client=llm_client)
    validator = ResultValidator()
    mentor = SecurityMentor(llm_client=llm_client)
    report_gen = ReportGenerator(repo=repo)

    specialists = {
        "recon": ReconSpecialist(runner),
        "web_security": WebSecuritySpecialist(runner),
        "api_security": ApiSecuritySpecialist(runner),
        "ai_security": AiSecuritySpecialist(runner),
    }

    def emit(state: SenseiState, msg: str) -> None:
        state.setdefault("execution_logs", []).append(msg)
        if status_callback:
            status_callback(msg)

    def scope_check_node(state: SenseiState) -> SenseiState:
        config = get_config()
        session_id = state["session_id"]
        instruction = state["instruction"]
        current_target = state.get("target") or ""
        extracted = planner_engine.extract_target_from_text(instruction, fallback_target=current_target)

        state["operating_mode"] = state.get("operating_mode") or config.mode.value
        state["execution_logs"] = state.get("execution_logs", [])
        state["reasoning_summaries"] = state.get("reasoning_summaries", [])
        state["tool_outputs"] = []
        state["raw_findings"] = []
        state["validated_findings"] = []
        state["pending_approvals"] = []
        state["budget_exceeded"] = False

        if "cost_tracker" not in state or state["cost_tracker"] is None:
            state["cost_tracker"] = CostTracker()

        if not extracted:
            state["target"] = ""
            state["target_authorized"] = False
            state["scope_reason"] = "No target specified. Register an authorized target with '/target <url>' or include it in your instruction."
            state["error"] = state["scope_reason"]
            emit(state, "Scope check halted: no target identified.")
            return state

        state["target"] = extracted
        scope_registry = get_scope_registry()
        in_scope, reason = scope_registry.is_in_scope(extracted)
        state["target_authorized"] = in_scope
        state["scope_reason"] = reason or ""

        get_audit_logger().log(
            session_id=session_id,
            action="scope_verification",
            actor="orchestrator",
            status="AUTHORIZED" if in_scope else "BLOCKED",
            target=extracted,
            details={"reason": state["scope_reason"]},
        )

        if not in_scope:
            state["error"] = (
                f"Authorization required: {state['scope_reason']} "
                f"Run '/scope authorize {extracted}' after verifying you have permission to test this target."
            )
            emit(state, f"Blocked by scope guardrails: {state['scope_reason']}")
        else:
            emit(state, f"Scope verified: {state['scope_reason']}")

        return state

    def planner_node(state: SenseiState) -> SenseiState:
        emit(state, f"Planning assessment for '{state['target']}'...")
        tracker = state["cost_tracker"]
        try:
            plan = planner_engine.create_plan(
                instruction=state["instruction"],
                target=state["target"],
                tracker=tracker,
            )
            state["plan"] = plan
            state["reasoning_summaries"].append(plan.reasoning_summary)
            emit(state, f"Generated plan '{plan.plan_id}' with {len(plan.steps)} step(s).")

            try:
                repo.save_plan(
                    session_id=state["session_id"],
                    objective=plan.objective,
                    steps=[s.model_dump() for s in plan.steps],
                    plan_id=plan.plan_id,
                )
            except Exception:
                pass
        except BudgetExceededError as be:
            state["budget_exceeded"] = True
            state["error"] = str(be)
            emit(state, str(be))
        return state

    def permission_gate_node(state: SenseiState) -> SenseiState:
        plan = state.get("plan")
        if not plan:
            return state

        mode = OperatingMode(state["operating_mode"])
        target_authorized = bool(state.get("target_authorized"))

        for step in plan.steps:
            risk = ActionRiskLevel(step.risk_level.upper()) if step.risk_level.upper() in ActionRiskLevel.__members__ else ActionRiskLevel.LOW
            decision = evaluate_permission(
                action_name=step.tool_name,
                risk_level=risk,
                mode=mode,
                is_target_authorized=target_authorized,
                description=step.description,
            )

            if not decision.allowed:
                step.status = "blocked"
                step.approval_status = "denied"
                step.result_summary = decision.reason
                emit(state, f"Step {step.step_index + 1} ({step.tool_name}) blocked: {decision.reason}")
                continue

            if decision.requires_approval:
                approved = False
                if approval_callback is not None:
                    approved = approval_callback(step, decision.reason)
                else:
                    req_id = f"{state['session_id'][:8]}-step-{step.step_index}"
                    req = ApprovalRequest(
                        request_id=req_id,
                        action_name=step.description,
                        target=state["target"],
                        risk_level=risk.value,
                        description=step.rationale or step.description,
                        tool_name=step.tool_name,
                        parameters=step.tool_input,
                    )
                    approved = get_approval_manager().request_approval(req)
                    if not approved:
                        state["pending_approvals"].append(req.model_dump())

                if approved:
                    step.status = "approved"
                    step.approval_status = "approved"
                    emit(state, f"Step {step.step_index + 1} ({step.tool_name}) approved by user.")
                else:
                    step.status = "skipped"
                    step.approval_status = "waiting"
                    step.result_summary = "Awaiting user approval."
                    emit(state, f"Step {step.step_index + 1} ({step.tool_name}) skipped/pending approval.")
            else:
                step.status = "approved"
                step.approval_status = "auto_approved"

        return state

    def execute_specialists_node(state: SenseiState) -> SenseiState:
        plan = state.get("plan")
        if not plan:
            return state

        for step in plan.steps:
            if step.status != "approved":
                continue

            specialist = specialists.get(step.specialist, specialists["web_security"])
            step.status = "running"
            emit(state, f"[{specialist.name}] Executing '{step.tool_name}' on {state['target']}...")

            output = specialist.execute_step(
                tool_name=step.tool_name,
                tool_input=step.tool_input,
                session_id=state["session_id"],
                target=state["target"],
                force_approved=True,
            )

            state["tool_outputs"].append(output)
            if output.success:
                step.status = "completed"
                step.result_summary = f"Completed in {output.duration_seconds:.2f}s with {len(output.findings)} finding(s)."
                state["raw_findings"].extend(output.findings)
                emit(state, f"[{specialist.name}] {step.tool_name} finished: {len(output.findings)} raw finding(s).")
            else:
                step.status = "failed"
                step.result_summary = output.error_message or "Execution failed"
                emit(state, f"[{specialist.name}] {step.tool_name} failed: {step.result_summary}")

        return state

    def validate_results_node(state: SenseiState) -> SenseiState:
        raw = state.get("raw_findings", [])
        validated = validator.validate(raw)
        state["validated_findings"] = validated
        emit(state, f"Result Validator verified {len(validated)} finding(s).")

        for f in validated:
            try:
                repo.save_finding(
                    session_id=state["session_id"],
                    finding_id=f.finding_id,
                    title=f.title,
                    description=f.description,
                    severity=f.severity.value,
                    affected_asset=f.affected_asset,
                    confidence=f.confidence_level.value,
                    evidence=f.evidence,
                    reproduction=f.reproduction_methodology,
                    impact=f.potential_impact,
                    remediation=f.remediation,
                    references=f.references,
                    validation_status=f.validation_status.value,
                )
            except Exception:
                pass
        return state

    def mentor_node(state: SenseiState) -> SenseiState:
        tracker = state["cost_tracker"]
        try:
            guidance = mentor.explain(
                objective=state["instruction"],
                target=state["target"],
                findings=state.get("validated_findings", []),
                tracker=tracker,
            )
            state["mentor_guidance"] = guidance
        except BudgetExceededError as be:
            state["budget_exceeded"] = True
            state["mentor_guidance"] = mentor._explain_deterministic(
                state["target"], state.get("validated_findings", [])
            )
            emit(state, f"{be} Fell back to local Security Mentor.")
        return state

    def reporting_node(state: SenseiState) -> SenseiState:
        plan = state.get("plan")
        tools_executed = [o.tool_name for o in state.get("tool_outputs", []) if o.success]
        methodology = [s.description for s in plan.steps] if plan else []
        report = report_gen.build_report(
            session_id=state["session_id"],
            target=state["target"],
            operating_mode=state["operating_mode"],
            findings=state.get("validated_findings", []),
            tools_executed=tools_executed,
            methodology=methodology,
            mentor_notes=state.get("mentor_guidance", ""),
        )
        state["report"] = report

        tracker = state.get("cost_tracker")
        if tracker:
            try:
                repo.update_session_usage(
                    session_id=state["session_id"],
                    tokens_delta=tracker.tokens_used,
                    cost_delta=tracker.cost_usd,
                )
            except Exception:
                pass

        emit(state, f"Security report '{report.report_id}' generated.")
        return state

    def route_after_scope(state: SenseiState) -> str:
        if not state.get("target_authorized"):
            return "end"
        return "planner"

    def route_after_planner(state: SenseiState) -> str:
        if state.get("budget_exceeded") or not state.get("plan"):
            return "end"
        return "permission_gate"

    graph = StateGraph(SenseiState)
    graph.add_node("scope_check", scope_check_node)
    graph.add_node("planner", planner_node)
    graph.add_node("permission_gate", permission_gate_node)
    graph.add_node("execute_specialists", execute_specialists_node)
    graph.add_node("validate_results", validate_results_node)
    graph.add_node("mentor_explain", mentor_node)
    graph.add_node("build_report", reporting_node)

    graph.set_entry_point("scope_check")
    graph.add_conditional_edges("scope_check", route_after_scope, {"planner": "planner", "end": END})
    graph.add_conditional_edges("planner", route_after_planner, {"permission_gate": "permission_gate", "end": END})
    graph.add_edge("permission_gate", "execute_specialists")
    graph.add_edge("execute_specialists", "validate_results")
    graph.add_edge("validate_results", "mentor_explain")
    graph.add_edge("mentor_explain", "build_report")
    graph.add_edge("build_report", END)

    return graph.compile()
