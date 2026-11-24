"""Typer CLI entry point for Sensei."""

from typing import Optional
import typer
from sensei.agent.orchestrator import SenseiOrchestrator
from sensei.config import OperatingMode, get_config
from sensei.main import InteractiveSession
from sensei.memory.database import init_db
from sensei.memory.repository import SenseiRepository
from sensei.reporting.generator import ReportGenerator
from sensei.security.scope import TargetScope, get_scope_registry
from sensei.terminal.ui import ask_terminal_approval, console, render_plan, render_report_summary
from sensei.terminal.views import show_doctor, show_history, show_tools

app = typer.Typer(
    name="sensei",
    help="Sensei — Autonomous AI Security Engineer. Test. Understand. Secure.",
    add_completion=False,
)

tools_app = typer.Typer(help="Inspect and manage Sensei security tool adapters.")
app.add_typer(tools_app, name="tools")


@app.callback(invoke_without_command=True)
def default_command(
    ctx: typer.Context,
    resume: Optional[str] = typer.Option(None, "--resume", "-r", help="Resume an existing session ID"),
) -> None:
    """Launch the interactive Sensei security engineering terminal."""
    if ctx.invoked_subcommand is None:
        session = InteractiveSession(session_id=resume)
        session.start()


@app.command("run")
def run_assessment(
    instruction: str = typer.Argument(..., help="Natural-language security assessment instruction"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Target URL, IP, or host"),
    authorize: bool = typer.Option(False, "--authorize", help="Explicitly authorize target in scope for this run"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Auto-approve non-restricted tool prompts"),
    mode: Optional[str] = typer.Option(None, "--mode", "-m", help="Operating mode: OBSERVE, COPILOT, AUTOPILOT"),
    report_format: Optional[str] = typer.Option(None, "--report-format", "-f", help="Export format: markdown, json, html"),
) -> None:
    """Execute a non-interactive security assessment from the command line."""
    init_db()
    config = get_config()
    if mode:
        try:
            config.mode = OperatingMode(mode.upper())
        except ValueError:
            console.print(f"[red]Invalid operating mode '{mode}'. Use OBSERVE, COPILOT, or AUTOPILOT.[/red]")
            raise typer.Exit(code=1)

    if authorize and target:
        get_scope_registry().add_scope(
            TargetScope(
                target=target,
                is_authorized=True,
                authorized_by="cli-flag",
                notes="Authorized via sensei run --authorize",
            )
        )

    def approval_cb(step, reason):
        if yes:
            return True
        return ask_terminal_approval(step.description, step.tool_name, step.risk_level, reason)

    orchestrator = SenseiOrchestrator(
        approval_callback=approval_cb,
        status_callback=lambda msg: console.print(f"  [dim]>[/dim] {msg}"),
    )

    state = orchestrator.run_instruction(instruction=instruction, target=target)

    if state.get("error"):
        console.print(f"[red]Error:[/red] {state['error']}")
        raise typer.Exit(code=2)

    if state.get("plan"):
        render_plan(state["plan"])

    if state.get("report"):
        report = state["report"]
        render_report_summary(report)
        if report_format:
            path = ReportGenerator(orchestrator.repo).save_report(report, fmt=report_format)
            console.print(f"[green]Report saved to:[/green] {path}")


@tools_app.command("list")
def tools_list() -> None:
    """List all registered security tools and their availability."""
    show_tools()


@app.command("history")
def history_cmd(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of recent sessions to display"),
) -> None:
    """Display historical assessment sessions from SQLite."""
    init_db()
    sessions = SenseiRepository().list_sessions(limit=limit)
    show_history(sessions)


@app.command("doctor")
def doctor_cmd() -> None:
    """Diagnose LLM provider keys, Ollama, Docker, and security tool availability."""
    show_doctor()


def main() -> None:
    """Package script entry point."""
    app()


if __name__ == "__main__":
    main()
