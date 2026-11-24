"""Reusable Rich terminal views for tools, status, history, doctor, and permissions."""

import shutil
from typing import List, Optional
from rich.panel import Panel
from rich.table import Table
from sensei.agent.llm import CostTracker, SenseiLLMClient
from sensei.config import get_config
from sensei.execution.docker import get_docker_sandbox
from sensei.memory.models import FindingRecord, SessionRecord
from sensei.security.approvals import get_approval_manager
from sensei.security.scope import get_scope_registry
from sensei.skills.loader import get_skill_loader
from sensei.terminal.ui import console
from sensei.tools.registry import get_tool_registry


def show_help() -> None:
    """Display available Sensei slash commands and natural language usage."""
    table = Table(title="Sensei Commands", border_style="cyan")
    table.add_column("Command", style="bold cyan", width=26)
    table.add_column("Description")

    mvp_cmds = [
        ("/help", "Show this help message"),
        ("/status", "Display active session, mode, LLM status, target, and budget"),
        ("/target <url_or_host>", "Set active target (prompts or checks scope authorization)"),
        ("/scope list|add|authorize|remove", "Manage authorized target scope registry"),
        ("/scan [target]", "Run an authorized non-destructive assessment against target"),
        ("/tools [list]", "List registered security tools and host availability"),
        ("/findings", "Display security findings from current session"),
        ("/report [markdown|json|html]", "Generate and export evidence-based security report"),
        ("/permissions [OBSERVE|COPILOT|AUTOPILOT]", "Inspect or change operating mode"),
        ("/approve <id>", "Approve a pending gated tool action"),
        ("/deny <id>", "Deny a pending gated tool action"),
        ("/clear", "Clear terminal screen"),
        ("/exit", "Exit Sensei session"),
    ]
    phase2_cmds = [
        ("/plan", "View the current execution plan"),
        ("/agents", "List specialist workflow agents and their tool boundaries"),
        ("/skills", "List available Markdown security methodology skills"),
        ("/memory", "Show persistent database statistics"),
        ("/history", "Show recent assessment sessions"),
        ("/sessions", "Alias for /history"),
        ("/resume <session_id>", "Resume a previous assessment session"),
    ]

    for cmd, desc in mvp_cmds:
        table.add_row(cmd, desc)
    for cmd, desc in phase2_cmds:
        table.add_row(f"[dim]{cmd}[/dim]", f"[dim]{desc}[/dim]")

    console.print(table)
    console.print("\n[dim]Or enter natural-language instructions directly, e.g.:[/dim]")
    console.print("  [italic]Audit http://localhost:3000 for security vulnerabilities.[/italic]\n")


def show_tools() -> None:
    """Render registered tools and their host availability status."""
    tools = get_tool_registry().list_all()
    table = Table(title="Sensei Tool Registry", border_style="cyan")
    table.add_column("Name", style="bold cyan", width=14)
    table.add_column("Category", width=24)
    table.add_column("Risk", width=8)
    table.add_column("Status", width=14)
    table.add_column("Description")

    for t in tools:
        status = "[green]Available[/green]" if t.is_available else "[yellow]Not Installed[/yellow]"
        table.add_row(t.name, t.category.value, t.required_permissions, status, t.description)

    console.print(table)


def show_status(
    session_id: str,
    active_target: str,
    tracker: CostTracker,
) -> None:
    """Show active session diagnostics."""
    config = get_config()
    llm_status = SenseiLLMClient(config).get_status()
    scopes = get_scope_registry().list_scopes()
    auth_count = sum(1 for s in scopes if s.is_authorized)

    body = (
        f"[bold]Session ID:[/bold] {session_id}\n"
        f"[bold]Operating Mode:[/bold] [cyan]{config.mode.value}[/cyan]\n"
        f"[bold]Active Target:[/bold] {active_target or '[dim]None[/dim]'}\n"
        f"[bold]Authorized Scopes:[/bold] {auth_count} registered\n"
        f"[bold]LLM Provider:[/bold] {llm_status.active_provider} ({llm_status.active_model})\n"
        f"[bold]Budget Usage:[/bold] {tracker.tokens_used}/{tracker.token_budget} tokens "
        f"(${tracker.cost_usd:.4f}/${tracker.cost_budget:.2f})"
    )
    console.print(Panel(body, title="Sensei Status", border_style="cyan"))


def show_doctor() -> None:
    """Inspect environment readiness: LLM keys, Ollama, Docker, and security tools."""
    config = get_config()
    llm_status = SenseiLLMClient(config).get_status()
    docker_ok = get_docker_sandbox().is_docker_available()

    table = Table(title="Sensei Environment Diagnostics (doctor)", border_style="cyan")
    table.add_column("Component", style="bold", width=22)
    table.add_column("Status", width=18)
    table.add_column("Details / Guidance")

    table.add_row(
        "OpenAI API Key",
        "[green]Configured[/green]" if llm_status.openai_configured else "[dim]Not Set[/dim]",
        "GPT-4o-mini active via LiteLLM" if llm_status.openai_configured else "Set OPENAI_API_KEY in .env (optional)",
    )
    table.add_row(
        "Groq API Key",
        "[green]Configured[/green]" if llm_status.groq_configured else "[dim]Not Set[/dim]",
        f"{config.groq_model} ready via LiteLLM" if llm_status.groq_configured else "Set GROQ_API_KEY in .env (optional)",
    )
    table.add_row(
        "Ollama Local LLM",
        "[green]Reachable[/green]" if llm_status.ollama_reachable else "[dim]Offline[/dim]",
        config.ollama_base_url if llm_status.ollama_reachable else "Start `ollama serve` for free local LLM synthesis",
    )
    table.add_row(
        "Docker Sandbox",
        "[green]Ready[/green]" if docker_ok else "[dim]Unavailable/Disabled[/dim]",
        "Container isolation ready" if docker_ok else f"DOCKER_ENABLED={config.docker_enabled}, docker binary={'found' if shutil.which('docker') else 'not found'}",
    )

    for tool in get_tool_registry().list_all():
        table.add_row(
            f"Tool: {tool.name}",
            "[green]Available[/green]" if tool.is_available else "[yellow]Missing[/yellow]",
            "Ready for execution" if tool.is_available else tool.install_guide,
        )

    console.print(table)
    if llm_status.guidance:
        console.print(f"\n[dim]LLM Note: {llm_status.guidance}[/dim]")


def show_history(sessions: List[SessionRecord]) -> None:
    """Display historical assessment sessions from SQLite."""
    if not sessions:
        console.print("[dim]No assessment sessions recorded yet.[/dim]")
        return

    table = Table(title="Assessment Session History", border_style="cyan")
    table.add_column("Session ID", style="cyan", width=36)
    table.add_column("Name", width=24)
    table.add_column("Mode", width=10)
    table.add_column("Tokens", justify="right", width=10)
    table.add_column("Updated")

    for s in sessions:
        table.add_row(
            s.id,
            s.name,
            s.mode,
            str(s.token_usage or 0),
            str(s.updated_at)[:19],
        )
    console.print(table)


def show_skills() -> None:
    """Display loaded Markdown security skills."""
    skills = get_skill_loader().load_all()
    table = Table(title=f"Sensei Security Skills ({len(skills)})", border_style="cyan")
    table.add_column("Skill", style="bold cyan", width=24)
    table.add_column("Tools", width=24)
    table.add_column("Objective")

    for s in skills:
        table.add_row(s.name, ", ".join(s.available_tools) or "-", s.objective[:90])
    console.print(table)


def show_agents() -> None:
    """Display specialist LangGraph workflow nodes."""
    table = Table(title="Specialist Security Workflows", border_style="cyan")
    table.add_column("Specialist", style="bold magenta", width=18)
    table.add_column("Permitted Tools", width=34)
    table.add_column("Responsibility")

    rows = [
        ("recon", "nmap, http_audit, semgrep, gitleaks, trivy", "Attack surface mapping and lightweight service discovery"),
        ("web_security", "http_audit, nuclei", "Non-destructive OWASP Top 10 web posture checks"),
        ("api_security", "http_audit, nuclei", "REST/GraphQL header, CORS, and endpoint audits"),
        ("ai_security", "http_audit", "LLM/AI endpoint exposure and guardrail checks"),
        ("mentor", "LLM / local knowledge", "Explains discovered issues and defense-in-depth fixes"),
    ]
    for name, tools, resp in rows:
        table.add_row(name, tools, resp)
    console.print(table)


def show_pending_approvals() -> None:
    """List pending approval requests."""
    pending = get_approval_manager().list_pending()
    if not pending:
        console.print("[dim]No pending approval requests.[/dim]")
        return
    for req in pending:
        console.print(f"- [yellow]{req.request_id}[/yellow]: {req.action_name} ({req.risk_level}) -> {req.target}")


def show_db_findings(records: List[FindingRecord]) -> None:
    """Display saved findings from SQLite when inspecting /findings."""
    if not records:
        console.print("[dim]No findings recorded in this session yet.[/dim]")
        return

    table = Table(title=f"Session Findings ({len(records)})", border_style="yellow")
    table.add_column("ID", style="cyan", width=26)
    table.add_column("Severity", width=14)
    table.add_column("Status", width=14)
    table.add_column("Title")
    table.add_column("Asset", style="dim")

    for r in records:
        table.add_row(r.finding_id, r.severity, r.validation_status, r.title, r.affected_asset)
    console.print(table)
