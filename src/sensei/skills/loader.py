"""Dynamic Markdown-based security skill loader."""

import re
from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from sensei.config import get_config


class SecuritySkill(BaseModel):
    """Parsed representation of a Markdown SKILL.md security methodology."""

    name: str
    title: str
    path: str
    when_to_use: str = ""
    objective: str = ""
    required_input: str = ""
    available_tools: List[str] = Field(default_factory=list)
    methodology: str = ""
    validation_criteria: str = ""
    safety_restrictions: str = ""
    expected_output: str = ""
    raw_content: str = ""


class SkillLoader:
    """Loads and selects relevant security methodology skills from skills/*/SKILL.md."""

    def __init__(self, skills_dir: Optional[Path] = None):
        self.skills_dir = skills_dir or get_config().skills_dir
        self._cache: Dict[str, SecuritySkill] = {}

    def load_all(self, refresh: bool = False) -> List[SecuritySkill]:
        """Discover and parse all SKILL.md files."""
        if self._cache and not refresh:
            return list(self._cache.values())

        self._cache.clear()
        if not self.skills_dir.exists():
            return []

        for skill_file in sorted(self.skills_dir.glob("*/SKILL.md")):
            skill_name = skill_file.parent.name
            parsed = self._parse_skill_file(skill_name, skill_file)
            if parsed:
                self._cache[skill_name] = parsed

        return list(self._cache.values())

    def get(self, name: str) -> Optional[SecuritySkill]:
        """Get a specific skill by folder name."""
        if not self._cache:
            self.load_all()
        return self._cache.get(name)

    def select_for_objective(self, objective: str) -> List[SecuritySkill]:
        """Dynamically select relevant skills based on the user's security objective."""
        skills = self.load_all()
        if not skills:
            return []

        obj_lower = objective.lower()
        selected: List[SecuritySkill] = []

        keyword_map = {
            "reconnaissance": ["recon", "port", "network", "nmap", "surface", "discover", "website", "audit", "assess"],
            "web-pentesting": ["web", "website", "http", "https", "owasp", "xss", "header", "audit", "assess", "scan"],
            "api-security": ["api", "rest", "graphql", "endpoint", "swagger", "openapi", "json"],
            "ai-security": ["ai", "llm", "chatbot", "agent", "rag", "model"],
            "prompt-injection": ["prompt", "injection", "jailbreak", "llm", "guardrail"],
            "vulnerability-validation": ["audit", "assess", "scan", "validate", "verify", "vulnerability"],
            "security-reporting": ["audit", "assess", "report", "summary", "explain", "scan"],
        }

        for skill in skills:
            keywords = keyword_map.get(skill.name, [])
            if any(kw in obj_lower for kw in keywords):
                selected.append(skill)

        # Default fallback for general assessments
        if not selected:
            for default_name in ("reconnaissance", "web-pentesting", "vulnerability-validation", "security-reporting"):
                s = self.get(default_name)
                if s:
                    selected.append(s)

        return selected

    def _parse_skill_file(self, name: str, path: Path) -> Optional[SecuritySkill]:
        """Parse sections from a Markdown SKILL.md document."""
        try:
            content = path.read_text(encoding="utf-8")
        except Exception:
            return None

        title_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
        title = title_match.group(1).strip() if title_match else name.replace("-", " ").title()

        sections: Dict[str, str] = {}
        current_header = None
        buffer: List[str] = []

        for line in content.splitlines():
            h2 = re.match(r"^##\s+(.+)$", line)
            if h2:
                if current_header:
                    sections[current_header] = "\n".join(buffer).strip()
                current_header = h2.group(1).strip().lower()
                buffer = []
            elif current_header:
                buffer.append(line)

        if current_header:
            sections[current_header] = "\n".join(buffer).strip()

        # Extract tool identifiers from `Available Tools` section
        tools_text = sections.get("available tools", "")
        tools = re.findall(r"`([a-zA-Z0-9_-]+)`", tools_text)

        return SecuritySkill(
            name=name,
            title=title,
            path=str(path),
            when_to_use=sections.get("when to use", ""),
            objective=sections.get("objective", ""),
            required_input=sections.get("required input", ""),
            available_tools=tools,
            methodology=sections.get("execution methodology", ""),
            validation_criteria=sections.get("validation criteria", ""),
            safety_restrictions=sections.get("safety restrictions", ""),
            expected_output=sections.get("expected output", ""),
            raw_content=content,
        )


_global_skill_loader: Optional[SkillLoader] = None


def get_skill_loader() -> SkillLoader:
    """Return global SkillLoader instance."""
    global _global_skill_loader
    if _global_skill_loader is None:
        _global_skill_loader = SkillLoader()
    return _global_skill_loader
