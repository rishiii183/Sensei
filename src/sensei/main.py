"""Interactive session controller for Sensei CLI."""

import shlex
from typing import Optional
from sensei.agent.llm import SenseiLLMClient
from sensei.agent.orchestrator import SenseiOrchestrator
from sensei.agent.state import PlanStep, SenseiState
from sensei.config import OperatingMode, get_config
from sensei.memory.database import init_db
from sensei.memory.repository import SenseiRepository
from sensei.reporting.generator import ReportGenerator
from sensei.reporting.models import SecurityReport
from sensei.security.approvals import get_approval_manager
from sensei.security.scope import TargetScope, get_scope_registry
from sensei.terminal.prompt import SenseiPrompt
from sensei.terminal.ui import (
    ask_terminal_approval,
    console,
    render_banner,
    render_findings,
    render_plan,
    render_report_summary,
)
from sensei.terminal.views import (
    show_agents,
    show_db_findings,
    show_help,
    show_history,
    show_pending_approvals,
    show_skills,
    show_status,
    show_tools,
)


class InteractiveSession:
    """Manages interactive command parsing, session persistence, and natural-language execution."""

    def __init__(self, session_id: Optional[str] = None):
        init_db()
        self.config = get_config()
        self.repo = SenseiRepository()
        self.llm = SenseiLLMClient(self.config)
        self.prompt = SenseiPrompt()
        self.active_target: str = ""
        self.last_state: Optional[SenseiState] = None
        self.last_report: Optional[SecurityReport] = None

        self.orchestrator = SenseiOrchestrator(
            session_id=session_id,
            repo=self.repo,
            llm_client=self.llm,
            approval_callback=self._approval_callback,
            status_callback=self._status_callback,
        )
        self._load_session_scopes()

    def _load_session_scopes(self) -> None:
        """Restore authorized scopes from SQLite when resuming a session."""
        scopes = self.repo.get_scopes(self.orchestrator.session_id)
        registry = get_scope_registry()
        for s in scopes:
            registry.add_scope(
                TargetScope(
                    target=s.target,
                    is_authorized=bool(s.is_authorized),
                    authorized_by=s.authorized_by or "user",
                    notes=s.notes or "",
                )
            )
            if s.is_authorized and not self.active_target:
                self.active_target = s.target

    def _status_callback(self, msg: str) -> None:
        console.print(f"  [dim]>[/dim] {msg}")

    def _approval_callback(self, step: PlanStep, reason: str) -> bool:
        return ask_terminal_approval(
            action_desc=step.description,
            tool_name=step.tool_name,
            risk_level=step.risk_level,
            reason=reason,
        )

    def start(self) -> None:
        """Launch interactive Sensei terminal loop."""
        llm_status = self.llm.get_status()
        render_banner(
            version="0.1.0",
            mode=self.config.mode.value,
            provider=f"{llm_status.active_provider}/{llm_status.active_model}",
        )
        if llm_status.active_provider == "local_heuristic":
            console.print(f"[dim]{llm_status.guidance}[/dim]\n")

        while True:
            try:
                raw = self.prompt.read_command("sensei > ").strip()
            except (EOFError, KeyboardInterrupt):
                console.print("\n[dim]Exiting Sensei. Stay secure.[/dim]")
                break

            if not raw:
                continue

            if raw.startswith("/"):
                should_continue = self.handle_command(raw)
                if not should_continue:
                    break
            else:
                self.handle_instruction(raw)

    def handle_command(self, raw: str) -> bool:
        """Dispatch slash commands. Returns False when user requests exit."""
        try:
            parts = shlex.split(raw)
        except ValueError:
            parts = raw.split()

        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ("/exit", "/quit"):
            console.print("[dim]Session saved. Exiting Sensei.[/dim]")
            return False

        elif cmd == "/clear":
            console.clear()

        elif cmd == "/help":
            show_help()

        elif cmd == "/status":
            show_status(
                session_id=self.orchestrator.session_id,
                active_target=self.active_target,
                tracker=self.orchestrator.cost_tracker,
            )

        elif cmd == "/target":
            if not args:
                console.print(f"Active target: [cyan]{self.active_target or 'None'}[/cyan]")
                console.print("[dim]Usage: /target <url_or_host>[/dim]")
            else:
                self._set_target(args[0])

        elif cmd == "/scope":
            self._handle_scope(args)

        elif cmd == "/scan":
            target = args[0] if args else self.active_target
            if not target:
                console.print("[yellow]No target set. Use '/target <url>' or '/scan <url>'.[/yellow]")
            else:
                self.handle_instruction(f"Perform a security assessment of {target}")

        elif cmd == "/tools":
            show_tools()

        elif cmd == "/findings":
            if self.last_state and self.last_state.get("validated_findings"):
                render_findings(self.last_state["validated_findings"])
            else:
                records = self.repo.get_findings(self.orchestrator.session_id)
                show_db_findings(records)

        elif cmd == "/report":
            self._handle_report(args)

        elif cmd == "/permissions":
            self._handle_permissions(args)

        elif cmd == "/approve":
            if not args:
                show_pending_approvals()
            else:
                ok = get_approval_manager().approve(args[0])
                console.print(
                    f"[green]Approved {args[0]}[/green]" if ok else f"[yellow]Request {args[0]} not found.[/yellow]"
                )

        elif cmd == "/deny":
            if not args:
                show_pending_approvals()
            else:
                ok = get_approval_manager().deny(args[0])
                console.print(
                    f"[yellow]Denied {args[0]}[/yellow]" if ok else f"[yellow]Request {args[0]} not found.[/yellow]"
                )

        elif cmd == "/plan":
            if self.last_state and self.last_state.get("plan"):
                render_plan(self.last_state["plan"])
            else:
                console.print("[dim]No assessment plan generated in this session yet.[/dim]")

        elif cmd == "/agents":
            show_agents()

        elif cmd == "/skills":
            show_skills()

        elif cmd == "/memory":
            sessions = self.repo.list_sessions()
            findings = self.repo.get_findings(self.orchestrator.session_id)
            console.print(
                f"Persistent SQLite Memory: [cyan]{len(sessions)}[/cyan] session(s), "
                f"[cyan]{len(findings)}[/cyan] finding(s) in current session."
            )

        elif cmd in ("/history", "/sessions"):
            show_history(self.repo.list_sessions())

        elif cmd == "/resume":
            if not args:
                console.print("[yellow]Usage: /resume <session_id>[/yellow]")
            else:
                self._resume_session(args[0])

        else:
            console.print(f"[yellow]Unknown command '{cmd}'. Type /help for available commands.[/yellow]")

        return True

    def _set_target(self, target: str) -> None:
        self.active_target = target
        registry = get_scope_registry()
        in_scope, reason = registry.is_in_scope(target)
        if in_scope:
            console.print(f"[green]Active target set to '{target}' (Authorized in scope).[/green]")
            return

        console.print(f"[yellow]Target '{target}' is not yet authorized in scope.[/yellow]")
        try:
            ans = console.input(
                f"[bold yellow]Confirm you have explicit authorization to test '{target}'? [y/N]: [/bold yellow]"
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"

        if ans in ("y", "yes"):
            self._authorize_target(target)
        else:
            console.print("[dim]Target recorded as unauthorized. Scope guardrails will block active testing.[/dim]")

    def _authorize_target(self, target: str) -> None:
        registry = get_scope_registry()
        registry.add_scope(
            TargetScope(
                target=target,
                is_authorized=True,
                authorized_by="user",
                notes="Authorized via CLI",
            )
        )
        self.repo.add_target_scope(
            session_id=self.orchestrator.session_id,
            target=target,
            is_authorized=True,
            authorized_by="user",
            notes="Authorized via CLI",
        )
        self.active_target = target
        console.print(f"[green]Authorized scope registered for '{target}'.[/green]")

    def _handle_scope(self, args: list[str]) -> None:
        registry = get_scope_registry()
        sub = args[0].lower() if args else "list"

        if sub == "list":
            scopes = registry.list_scopes()
            if not scopes:
                console.print("[dim]Scope registry is empty. Use '/scope authorize <target>' to register.[/dim]")
                return
            for s in scopes:
                badge = "[green]AUTHORIZED[/green]" if s.is_authorized else "[red]UNAUTHORIZED[/red]"
                console.print(f"- {s.target} [{badge}] (by {s.authorized_by})")
        elif sub in ("add", "authorize") and len(args) >= 2:
            self._authorize_target(args[1])
        elif sub == "remove" and len(args) >= 2:
            removed = registry.remove_scope(args[1])
            console.print(f"Removed '{args[1]}': {removed}")
        else:
            console.print("[dim]Usage: /scope [list | authorize <target> | remove <target>][/dim]")

    def _handle_permissions(self, args: list[str]) -> None:
        if not args:
            console.print(f"Current Operating Mode: [bold cyan]{self.config.mode.value}[/bold cyan]")
            console.print("[dim]Modes: OBSERVE (ask all), COPILOT (default, ask medium/high), AUTOPILOT (strict bounded)[/dim]")
            return
        try:
            new_mode = OperatingMode(args[0].upper())
            self.config.mode = new_mode
            console.print(f"[green]Operating mode switched to {new_mode.value}.[/green]")
        except ValueError:
            console.print("[red]Invalid mode. Choose OBSERVE, COPILOT, or AUTOPILOT.[/red]")

    def _handle_report(self, args: list[str]) -> None:
        if not self.last_report:
            console.print("[yellow]No assessment report available yet. Run a scan first.[/yellow]")
            return
        fmt = args[0].lower() if args else "terminal"
        if fmt == "terminal":
            render_report_summary(self.last_report)
        else:
            gen = ReportGenerator(self.repo)
            try:
                path = gen.save_report(self.last_report, fmt=fmt)
                console.print(f"[green]Report exported to:[/green] {path}")
            except ValueError as e:
                console.print(f"[red]{e}[/red]")

    def _resume_session(self, session_id: str) -> None:
        rec = self.repo.get_session(session_id)
        if not rec:
            # Allow prefix match for convenience
            matches = [s for s in self.repo.list_sessions(50) if s.id.startswith(session_id)]
            rec = matches[0] if len(matches) == 1 else None

        if not rec:
            console.print(f"[red]Session '{session_id}' not found.[/red]")
            return

        self.orchestrator = SenseiOrchestrator(
            session_id=rec.id,
            repo=self.repo,
            llm_client=self.llm,
            approval_callback=self._approval_callback,
            status_callback=self._status_callback,
        )
        self.active_target = ""
        self._load_session_scopes()
        console.print(f"[green]Resumed session {rec.id} ({rec.name}).[/green]")

    def handle_instruction(self, instruction: str) -> None:
        """Execute natural-language security instruction via LangGraph orchestrator."""
        from sensei.agent.planner import PlanningEngine

        scope_reg = self.orchestrator.runner.scope_registry
        target_candidate = PlanningEngine.extract_target_from_text(instruction, self.active_target)
        if not target_candidate:
            try:
                entered = console.input(
                    "[bold yellow]Which target URL or host should Sensei assess (e.g. http://localhost:3000)? [/bold yellow]"
                ).strip()
                if entered:
                    target_candidate = entered
                    self.active_target = entered
            except (EOFError, KeyboardInterrupt):
                pass

        if target_candidate:
            in_scope, _ = scope_reg.is_in_scope(target_candidate)
            if not in_scope:
                console.print(f"[yellow]Target '{target_candidate}' is not in the authorized scope registry.[/yellow]")
                try:
                    ans = console.input(
                        f"[bold yellow]Do you have authorization to assess '{target_candidate}'? Authorize now? [y/N]: [/bold yellow]"
                    ).strip().lower()
                    if ans in ("y", "yes"):
                        self._authorize_target(target_candidate)
                except (EOFError, KeyboardInterrupt):
                    pass

        console.print(f"\n[bold cyan]Sensei Orchestrator[/bold cyan] starting assessment...")
        state = self.orchestrator.run_instruction(instruction=instruction, target=self.active_target)
        self.last_state = state

        if state.get("error"):
            console.print(f"\n[red]Assessment halted:[/red] {state['error']}")
            if state.get("budget_exceeded"):
                try:
                    ans = console.input("[yellow]Increase/override scan budget to continue? [y/N]: [/yellow]").strip().lower()
                    if ans in ("y", "yes"):
                        self.orchestrator.cost_tracker.budget_override_approved = True
                        state = self.orchestrator.run_instruction(instruction=instruction, target=self.active_target)
                        self.last_state = state
                except (EOFError, KeyboardInterrupt):
                    pass
            if state.get("error"):
                return

        if state.get("plan"):
            console.print()
            render_plan(state["plan"])

        if state.get("report"):
            self.last_report = state["report"]
            render_report_summary(self.last_report)
