"""Configuration management for Sensei Autonomous AI Security Engineer."""

import os
from enum import Enum
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class OperatingMode(str, Enum):
    """Sensei operating security modes."""
    OBSERVE = "OBSERVE"      # Explain proposed operations, plans, wait for individual approvals
    COPILOT = "COPILOT"      # Default: execute permitted low-risk ops, request approval for higher risk
    AUTOPILOT = "AUTOPILOT"  # Execute predefined authorized workflows under strict scope limits


class SenseiConfig(BaseModel):
    """Central configuration for Sensei agent and runtime."""

    # Provider & Model Settings
    openai_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("OPENAI_API_KEY") or None
    )
    default_model: str = Field(
        default_factory=lambda: os.getenv("DEFAULT_MODEL", "openai/gpt-4o-mini")
    )
    groq_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("GROQ_API_KEY") or None
    )
    groq_model: str = Field(
        default_factory=lambda: os.getenv("GROQ_MODEL", "groq/llama-3.3-70b-versatile")
    )
    ollama_base_url: str = Field(
        default_factory=lambda: os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    )
    ollama_model: str = Field(
        default_factory=lambda: os.getenv("OLLAMA_MODEL", "ollama/llama3.2")
    )

    # Operating Mode (Default: COPILOT)
    mode: OperatingMode = Field(
        default_factory=lambda: OperatingMode(os.getenv("SENSEI_MODE", "COPILOT").upper())
    )

    # Cost & Token Budget Controls
    per_scan_token_budget: int = Field(
        default_factory=lambda: int(os.getenv("PER_SCAN_TOKEN_BUDGET", "150000"))
    )
    per_scan_cost_budget: float = Field(
        default_factory=lambda: float(os.getenv("PER_SCAN_COST_BUDGET", "1.50"))
    )
    max_tool_output_chars: int = Field(
        default_factory=lambda: int(os.getenv("MAX_TOOL_OUTPUT_CHARS", "3000"))
    )

    # Tool Execution Rate Limits (actions/sec)
    tool_rate_limit: float = Field(
        default_factory=lambda: float(os.getenv("TOOL_RATE_LIMIT", "2.0"))
    )

    # Database
    database_url: str = Field(
        default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///sensei.db")
    )

    # Docker Sandbox Execution
    docker_enabled: bool = Field(
        default_factory=lambda: os.getenv("DOCKER_ENABLED", "false").lower() in ("true", "1", "yes")
    )

    # Directory Paths
    base_dir: Path = Field(default_factory=lambda: Path(os.getcwd()))
    reports_dir: Path = Field(default_factory=lambda: Path("reports"))
    skills_dir: Path = Field(default_factory=lambda: Path("skills"))

    def has_openai_key(self) -> bool:
        """Check if a valid OpenAI API key is present."""
        return bool(self.openai_api_key and self.openai_api_key.strip() and not self.openai_api_key.startswith("your-"))

    def has_groq_key(self) -> bool:
        """Check if a valid Groq API key is present."""
        return bool(self.groq_api_key and self.groq_api_key.strip() and not self.groq_api_key.startswith("your-"))

    def get_effective_model(self) -> str:
        """Return the effective LLM model, falling back to Groq, Ollama, or local heuristic."""
        if self.has_openai_key():
            return self.default_model
        if self.has_groq_key():
            return self.groq_model
        return self.ollama_model


# Global singleton config
_config_instance: Optional[SenseiConfig] = None


def get_config() -> SenseiConfig:
    """Retrieve or initialize the global Sensei configuration."""
    global _config_instance
    if _config_instance is None:
        _config_instance = SenseiConfig()
        _config_instance.reports_dir.mkdir(parents=True, exist_ok=True)
    return _config_instance


def reset_config(config: Optional[SenseiConfig] = None) -> None:
    """Reset configuration singleton (useful for testing)."""
    global _config_instance
    _config_instance = config
