"""Web Security Specialist Node."""

from typing import Set
from sensei.execution.runner import ToolExecutionRunner
from sensei.tools.schemas import ToolOutput

ALLOWED_WEB_TOOLS: Set[str] = {"http_audit", "nuclei", "reflection_audit", "dom_audit"}


class WebSecuritySpecialist:
    """Executes non-destructive web application security checks."""

    name = "web_security"

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
        if tool_name not in ALLOWED_WEB_TOOLS:
            return ToolOutput(
                tool_name=tool_name,
                success=False,
                exit_code=-20,
                error_message=f"WebSecuritySpecialist is not permitted to invoke tool '{tool_name}'.",
            )
        return self.runner.run_tool(
            tool_name=tool_name,
            input_data=tool_input,
            session_id=session_id,
            target=target,
            force_approved=force_approved,
        )
