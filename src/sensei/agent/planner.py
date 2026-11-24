"""Structured Planning Engine for translating natural-language instructions into safe assessment plans."""

import json
import re
import uuid
from typing import List, Optional
from sensei.agent.llm import CostTracker, SenseiLLMClient
from sensei.agent.state import AssessmentPlan, PlanStep
from sensei.skills.loader import get_skill_loader
from sensei.tools.registry import get_tool_registry


class PlanningEngine:
    """Generates structured, tool-constrained execution plans from user instructions."""

    def __init__(self, llm_client: Optional[SenseiLLMClient] = None):
        self.llm = llm_client or SenseiLLMClient()

    @staticmethod
    def extract_target_from_text(instruction: str, fallback_target: str = "") -> str:
        """Extract URL, IP, or hostname from natural-language text if present."""
        url_match = re.search(r"https?://[^\s'\"<>]+", instruction, re.IGNORECASE)
        if url_match:
            return url_match.group(0).rstrip(".,;)")

        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b", instruction)
        if ip_match:
            return ip_match.group(0)

        host_match = re.search(
            r"\b(?:localhost(?::\d{1,5})?|[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+(?::\d{1,5})?)\b",
            instruction,
        )
        if host_match:
            candidate = host_match.group(0)
            if not candidate.endswith((".py", ".md", ".json", ".yaml")):
                return candidate

        return fallback_target

    def create_plan(
        self,
        instruction: str,
        target: str,
        tracker: Optional[CostTracker] = None,
    ) -> AssessmentPlan:
        """
        Generate an AssessmentPlan using available skills and registered tools.
        Uses LiteLLM if configured and reachable, otherwise uses deterministic security planning.
        """
        skill_loader = get_skill_loader()
        selected_skills = skill_loader.select_for_objective(instruction)
        skill_names = [s.name for s in selected_skills]

        registry = get_tool_registry()
        available_tools = registry.list_all()
        tool_summaries = [
            f"{t.name} ({t.category.value}, available={t.is_available}, risk={t.required_permissions}): {t.description}"
            for t in available_tools
        ]

        llm_status = self.llm.get_status()
        if llm_status.active_provider != "local_heuristic":
            plan = self._plan_with_llm(instruction, target, skill_names, tool_summaries, tracker)
            if plan is not None:
                return plan

        return self._plan_deterministic(instruction, target, skill_names)

    def _plan_with_llm(
        self,
        instruction: str,
        target: str,
        skill_names: List[str],
        tool_summaries: List[str],
        tracker: Optional[CostTracker],
    ) -> Optional[AssessmentPlan]:
        """Attempt structured JSON plan synthesis via LiteLLM."""
        system_prompt = (
            "You are Sensei's Planning Engine, an authorized defensive cybersecurity architect. "
            "Given an assessment objective and target, produce a concise, non-destructive execution plan "
            "using ONLY tools from the provided tool registry. Never invent shell commands.\n"
            "Return ONLY valid JSON with keys: reasoning_summary (string) and steps (list of objects with: "
            "specialist [recon|web_security|api_security|ai_security], description, tool_name, risk_level [SAFE|LOW|MEDIUM], rationale)."
        )
        user_prompt = (
            f"Objective: {instruction}\n"
            f"Target: {target}\n"
            f"Relevant Skills: {', '.join(skill_names)}\n"
            f"Registered Tools:\n" + "\n".join(f"- {s}" for s in tool_summaries)
        )

        content, _ = self.llm.complete(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            tracker=tracker,
            temperature=0.1,
            max_tokens=700,
        )
        if not content:
            return None

        try:
            json_match = re.search(r"\{.*\}", content, re.DOTALL)
            raw_json = json_match.group(0) if json_match else content
            parsed = json.loads(raw_json)
            registry = get_tool_registry()

            steps: List[PlanStep] = []
            for idx, item in enumerate(parsed.get("steps", [])):
                tool_name = str(item.get("tool_name", "")).strip()
                adapter = registry.get(tool_name)
                if not adapter:
                    continue
                risk = str(item.get("risk_level", adapter.info.required_permissions)).upper()
                if risk not in ("SAFE", "LOW", "MEDIUM", "HIGH"):
                    risk = adapter.info.required_permissions

                steps.append(
                    PlanStep(
                        step_index=len(steps),
                        specialist=str(item.get("specialist", "web_security")),
                        description=str(item.get("description", f"Run {tool_name} against {target}")),
                        tool_name=tool_name,
                        risk_level=risk,
                        tool_input={"target": target} if tool_name not in ("semgrep", "gitleaks") else {"target_path": target, "source": target},
                        rationale=str(item.get("rationale", "")),
                    )
                )

            if not steps:
                return None

            return AssessmentPlan(
                plan_id=str(uuid.uuid4())[:8],
                objective=instruction,
                target=target,
                selected_skills=skill_names,
                steps=steps,
                reasoning_summary=str(parsed.get("reasoning_summary", "Structured security plan generated via LLM.")),
            )
        except Exception:
            return None

    def _plan_deterministic(
        self,
        instruction: str,
        target: str,
        skill_names: List[str],
    ) -> AssessmentPlan:
        """Create a sound deterministic security plan based on objective and available tools."""
        registry = get_tool_registry()
        obj_lower = instruction.lower()
        steps: List[PlanStep] = []

        # Code / Repo / Secret audit path
        if any(k in obj_lower for k in ("code", "repo", "secret", "sast", "source", "container", "docker")):
            if registry.get("semgrep") and registry.get("semgrep").check_availability():
                steps.append(
                    PlanStep(
                        step_index=len(steps),
                        specialist="recon",
                        description="Run static application security analysis with Semgrep",
                        tool_name="semgrep",
                        risk_level="LOW",
                        tool_input={"target_path": target or "."},
                        rationale="Detect insecure coding patterns without executing code.",
                    )
                )
            if registry.get("gitleaks") and registry.get("gitleaks").check_availability():
                steps.append(
                    PlanStep(
                        step_index=len(steps),
                        specialist="recon",
                        description="Scan repository for accidental hardcoded secrets with Gitleaks",
                        tool_name="gitleaks",
                        risk_level="LOW",
                        tool_input={"source": target or "."},
                        rationale="Prevent credential leakage in source files.",
                    )
                )
            if registry.get("trivy") and registry.get("trivy").check_availability():
                steps.append(
                    PlanStep(
                        step_index=len(steps),
                        specialist="recon",
                        description="Scan dependencies and container artifacts for known CVEs with Trivy",
                        tool_name="trivy",
                        risk_level="LOW",
                        tool_input={"target": target or "."},
                        rationale="Identify vulnerable packages and misconfigurations.",
                    )
                )

        # Web / API / General Website Audit path (Default)
        if not steps:
            if registry.get("nmap") and registry.get("nmap").check_availability():
                steps.append(
                    PlanStep(
                        step_index=len(steps),
                        specialist="recon",
                        description=f"Perform lightweight non-intrusive service discovery on {target}",
                        tool_name="nmap",
                        risk_level="LOW",
                        tool_input={"target": target, "ports": "80,443,3000,8000,8080"},
                        rationale="Map open HTTP/API ports and service banners before application checks.",
                    )
                )

            # Native safe HTTP security auditor (always available)
            steps.append(
                PlanStep(
                    step_index=len(steps),
                    specialist="api_security" if "api" in obj_lower else "web_security",
                    description=f"Run non-destructive HTTP security audit (headers, cookies, sensitive exposures) on {target}",
                    tool_name="http_audit",
                    risk_level="LOW",
                    tool_input={"target": target},
                    rationale="Verify defensive HTTP headers, cookie security flags, server leaks, and sensitive paths safely.",
                )
            )

            # Nuclei safe template assessment
            nuclei_adapter = registry.get("nuclei")
            if nuclei_adapter and nuclei_adapter.check_availability():
                steps.append(
                    PlanStep(
                        step_index=len(steps),
                        specialist="web_security",
                        description=f"Run Nuclei with safe, non-destructive templates (tech, misconfig, info/low CVEs) on {target}",
                        tool_name="nuclei",
                        risk_level="LOW",
                        tool_input={"target": target, "severity": "info,low", "tags": "cve,misconfig,tech"},
                        rationale="Detect known template-matched misconfigurations and technologies under strict rate limits.",
                    )
                )

        reasoning = (
            f"Planned {len(steps)} non-destructive assessment step(s) targeting '{target}' "
            f"guided by skills [{', '.join(skill_names)}]. All steps enforce scope verification and rate limits."
        )

        return AssessmentPlan(
            plan_id=str(uuid.uuid4())[:8],
            objective=instruction,
            target=target,
            selected_skills=skill_names,
            steps=steps,
            reasoning_summary=reasoning,
        )
