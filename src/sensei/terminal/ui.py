"""Rich terminal UI components for Sensei."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from sensei.agent.state import AssessmentPlan
from sensei.reporting.models import Finding, SecurityReport, SeverityLevel

console = Console()

SEVERITY_COLORS = {
    SeverityLevel.CRITICAL: "bold red",
    SeverityLevel.HIGH: "red",
    SeverityLevel.MEDIUM: "yellow",
    SeverityLevel.LOW: "cyan",
    SeverityLevel.INFORMATIONAL: "dim white",
}


def render_banner(version: str = "0.1.0", mode: str = "COPILOT", provider: str = "openai") -> None:
    """Render clean, minimal professional Sensei terminal branding."""
    header = Text()
    header.append("SENSEI\n", style="bold cyan")
    header.append("Autonomous AI Security Engineer\n", style="bold white")
    header.append("Test. Understand. Secure.\n", style="italic dim")
    header.append(f"Version: {version}  |  Mode: {mode}  |  LLM: {provider}", style="dim")

    console.print(Panel(header, border_style="cyan", padding=(1, 2)))
    console.print("[bold]Welcome back.[/bold]")
    console.print("[dim]What would you like to investigate? (Type /help for commands)[/dim]\n")


def render_plan(plan: AssessmentPlan) -> None:
    """Display structured execution plan cleanly."""
    table = Table(title=f"Assessment Plan [{plan.plan_id}] -> {plan.target}", border_style="cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column("Specialist", style="magenta", width=14)
    table.add_column("Tool", style="cyan", width=12)
    table.add_column("Risk", width=8)
    table.add_column("Status", width=12)
    table.add_column("Description")

    for step in plan.steps:
        risk_style = "green" if step.risk_level in ("SAFE", "LOW") else "yellow"
        table.add_row(
            str(step.step_index + 1),
            step.specialist,
            step.tool_name,
            f"[{risk_style}]{step.risk_level}[/{risk_style}]",
            step.status,
            step.description,
        )

    console.print(table)
    if plan.reasoning_summary:
        console.print(f"[dim]Reasoning: {plan.reasoning_summary}[/dim]\n")


def render_findings(findings: list[Finding]) -> None:
    """Render validated findings in a structured Rich table and detail cards."""
    if not findings:
        console.print(Panel("[green]No vulnerabilities or misconfigurations identified.[/green]", border_style="green"))
        return

    table = Table(title=f"Security Findings ({len(findings)})", border_style="yellow")
    table.add_column("ID", style="cyan", width=26)
    table.add_column("Severity", width=14)
    table.add_column("Validation", width=14)
    table.add_column("Title")
    table.add_column("Asset", style="dim")

    for f in findings:
        sev_style = SEVERITY_COLORS.get(f.severity, "white")
        table.add_row(
            f.finding_id,
            f"[{sev_style}]{f.severity.value}[/{sev_style}]",
            f.validation_status.value,
            f.title,
            f.affected_asset,
        )

    console.print(table)

    console.print("\n[bold]Detailed Evidence & Remediation:[/bold]")
    for idx, f in enumerate(findings, start=1):
        sev_style = SEVERITY_COLORS.get(f.severity, "white")
        body = (
            f"[bold]Asset:[/bold] {f.affected_asset}\n"
            f"[bold]Status:[/bold] {f.validation_status.value} (Confidence: {f.confidence_level.value})\n"
            f"[bold]Description:[/bold] {f.description}\n"
            f"[bold]Evidence:[/bold] {f.evidence}\n"
            f"[bold]Remediation:[/bold] {f.remediation}"
        )
        console.print(
            Panel(
                body,
                title=f"{idx}. [{sev_style}]{f.severity.value}[/{sev_style}] {f.title}",
                border_style="dim",
            )
        )


def render_report_summary(report: SecurityReport) -> None:
    """Render executive report summary and Security Mentor explanation."""
    console.print(
        Panel(
            f"[bold]{report.title}[/bold]\n"
            f"Report ID: [cyan]{report.report_id}[/cyan] | Target: [cyan]{report.target}[/cyan]\n\n"
            f"{report.executive_summary}",
            title="Security Assessment Report",
            border_style="cyan",
        )
    )
    render_findings(report.findings)

    if report.mentor_notes:
        console.print(
            Panel(
                report.mentor_notes,
                title="Security Mentor — Understand & Secure",
                border_style="green",
            )
        )


def ask_terminal_approval(action_desc: str, tool_name: str, risk_level: str, reason: str) -> bool:
    """Prompt user cleanly in terminal for approval before running a gated action."""
    console.print(
        Panel(
            f"[bold]Tool:[/bold] {tool_name}\n"
            f"[bold]Risk Level:[/bold] [yellow]{risk_level}[/yellow]\n"
            f"[bold]Action:[/bold] {action_desc}\n"
            f"[bold]Policy Reason:[/bold] {reason}",
            title="Permission Approval Required",
            border_style="yellow",
        )
    )
    try:
        answer = console.input("[bold yellow]Approve this action? [y/N]: [/bold yellow]").strip().lower()
        return answer in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False
