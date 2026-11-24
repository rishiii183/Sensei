"""Reconnaissance Specialist Node."""

from typing import Set
from sensei.execution.runner import ToolExecutionRunner
from sensei.tools.schemas import ToolOutput

ALLOWED_RECON_TOOLS: Set[str] = {"nmap", "http_audit", "semgrep", "gitleaks", "trivy"}


class ReconSpecialist:
    """Handles attack surface mapping and passive/lightweight service discovery."""

    name = "recon"

    def __init__(self, runner: ToolExecutionRunner):
        self.runner = runner

    def execute_step(
        self,
        tool_name: str,
        tool_input: dict,
        session_id: str,
        target: str,
        force_approved: bool = False,
    ) -> ToolOutput:
        if tool_name not in ALLOWED_RECON_TOOLS:
            return ToolOutput(
                tool_name=tool_name,
                success=False,
                exit_code=-20,
                error_message=f"ReconSpecialist is not permitted to invoke tool '{tool_name}'.",
            )
        return self.runner.run_tool(
            tool_name=tool_name,
            input_data=tool_input,
            session_id=session_id,
            target=target,
            force_approved=force_approved,
        )
