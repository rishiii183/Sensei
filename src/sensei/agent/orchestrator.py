"""High-level Sensei Orchestrator wrapping the LangGraph execution workflow."""

import uuid
from typing import Optional
from sensei.agent.graph import ApprovalCallback, StatusCallback, build_sensei_graph
from sensei.agent.llm import CostTracker, SenseiLLMClient
from sensei.agent.state import SenseiState
from sensei.config import get_config
from sensei.execution.runner import ToolExecutionRunner
from sensei.memory.database import init_db
from sensei.memory.repository import SenseiRepository


class SenseiOrchestrator:
    """Coordinates assessments, session state, budgets, and reporting."""

    def __init__(
        self,
        session_id: Optional[str] = None,
        repo: Optional[SenseiRepository] = None,
        llm_client: Optional[SenseiLLMClient] = None,
        approval_callback: Optional[ApprovalCallback] = None,
        status_callback: Optional[StatusCallback] = None,
    ):
        init_db()
        self.repo = repo or SenseiRepository()
        self.llm_client = llm_client or SenseiLLMClient()
        self.runner = ToolExecutionRunner(repo=self.repo)
        self.approval_callback = approval_callback
        self.status_callback = status_callback
        self.config = get_config()

        if session_id:
            existing = self.repo.get_session(session_id)
            if existing:
                self.session_id = existing.id
            else:
                rec = self.repo.create_session(name=f"Session {session_id[:8]}", mode=self.config.mode.value, session_id=session_id)
                self.session_id = rec.id
        else:
            rec = self.repo.create_session(name="Security Assessment", mode=self.config.mode.value)
            self.session_id = rec.id

        self.cost_tracker = CostTracker(
            token_budget=self.config.per_scan_token_budget,
            cost_budget=self.config.per_scan_cost_budget,
        )

    def run_instruction(
        self,
        instruction: str,
        target: Optional[str] = None,
    ) -> SenseiState:
        """Execute an assessment instruction through the LangGraph pipeline."""
        graph = build_sensei_graph(
            runner=self.runner,
            repo=self.repo,
            llm_client=self.llm_client,
            approval_callback=self.approval_callback,
            status_callback=self.status_callback,
        )

        initial_state: SenseiState = {
            "session_id": self.session_id,
            "instruction": instruction,
            "target": target or "",
            "operating_mode": self.config.mode.value,
            "cost_tracker": self.cost_tracker,
            "execution_logs": [],
            "reasoning_summaries": [],
        }

        final_state = graph.invoke(initial_state)
        return final_state
