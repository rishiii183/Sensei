"""Provider-independent LLM abstraction using LiteLLM with budget enforcement and graceful fallback."""

import os
from typing import Any, Dict, List, Optional, Tuple
import httpx
from pydantic import BaseModel, Field
from sensei.config import SenseiConfig, get_config


class BudgetExceededError(Exception):
    """Raised when per-scan token or cost budget would be exceeded."""

    def __init__(self, tokens_used: int, token_budget: int, cost_used: float, cost_budget: float):
        self.tokens_used = tokens_used
        self.token_budget = token_budget
        self.cost_used = cost_used
        self.cost_budget = cost_budget
        super().__init__(
            f"Per-scan budget limit reached (tokens: {tokens_used}/{token_budget}, "
            f"cost: ${cost_used:.4f}/${cost_budget:.2f}). Approval required to continue."
        )


class CostTracker(BaseModel):
    """Tracks token and USD cost consumption per scan."""

    tokens_used: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    token_budget: int = Field(default_factory=lambda: get_config().per_scan_token_budget)
    cost_budget: float = Field(default_factory=lambda: get_config().per_scan_cost_budget)
    budget_override_approved: bool = False

    def check_budget(self) -> None:
        """Raise BudgetExceededError if limits are reached and not overridden."""
        if self.budget_override_approved:
            return
        if self.tokens_used >= self.token_budget or self.cost_usd >= self.cost_budget:
            raise BudgetExceededError(
                self.tokens_used, self.token_budget, self.cost_usd, self.cost_budget
            )

    def record_usage(self, prompt_tokens: int, completion_tokens: int, cost_usd: float = 0.0) -> None:
        """Update cumulative counters."""
        self.prompt_tokens += prompt_tokens
        self.completion_tokens += completion_tokens
        self.tokens_used += prompt_tokens + completion_tokens
        self.cost_usd += cost_usd


class LLMStatus(BaseModel):
    """Diagnostic status of configured LLM providers."""

    active_provider: str
    active_model: str
    openai_configured: bool
    groq_configured: bool = False
    ollama_reachable: bool = False
    guidance: str = ""


class SenseiLLMClient:
    """LiteLLM wrapper supporting OpenAI GPT-4o-mini, Ollama fallback, and graceful offline mode."""

    def __init__(self, config: Optional[SenseiConfig] = None):
        self.config = config or get_config()

    def is_ollama_available(self, timeout: float = 1.5) -> bool:
        """Check if a local Ollama server is running."""
        try:
            url = f"{self.config.ollama_base_url.rstrip('/')}/api/tags"
            is_local = "localhost" in url or "127.0.0.1" in url
            resp = httpx.get(url, timeout=timeout, trust_env=not is_local)
            return resp.status_code == 200
        except Exception:
            return False

    def get_status(self) -> LLMStatus:
        """Return clear diagnostic info about LLM availability and setup instructions."""
        has_openai = self.config.has_openai_key()
        has_groq = self.config.has_groq_key()
        ollama_ok = self.is_ollama_available()

        if has_openai:
            return LLMStatus(
                active_provider="openai",
                active_model=self.config.default_model,
                openai_configured=True,
                groq_configured=has_groq,
                ollama_reachable=ollama_ok,
                guidance="OpenAI API key configured.",
            )
        if has_groq:
            return LLMStatus(
                active_provider="groq",
                active_model=self.config.groq_model,
                openai_configured=False,
                groq_configured=True,
                ollama_reachable=ollama_ok,
                guidance=f"Groq API key configured ({self.config.groq_model} active via LiteLLM).",
            )
        if ollama_ok:
            return LLMStatus(
                active_provider="ollama",
                active_model=self.config.ollama_model,
                openai_configured=False,
                groq_configured=False,
                ollama_reachable=True,
                guidance=(
                    "No OPENAI_API_KEY or GROQ_API_KEY found. Using local Ollama fallback. "
                    "Add OPENAI_API_KEY or GROQ_API_KEY to .env to use cloud models."
                ),
            )
        return LLMStatus(
            active_provider="local_heuristic",
            active_model="sensei-offline-engine",
            openai_configured=False,
            groq_configured=False,
            ollama_reachable=False,
            guidance=(
                "No OPENAI_API_KEY or GROQ_API_KEY configured and local Ollama is not running. "
                "Running in local deterministic security mode (all local scans, planning, and reporting remain usable). "
                "Add OPENAI_API_KEY or GROQ_API_KEY to .env, or start Ollama (`ollama serve`), to enable AI synthesis."
            ),
        )

    def complete(
        self,
        messages: List[Dict[str, str]],
        tracker: Optional[CostTracker] = None,
        temperature: float = 0.1,
        max_tokens: int = 800,
    ) -> Tuple[Optional[str], Dict[str, Any]]:
        """
        Execute an LLM completion via LiteLLM with budget check.
        Returns (content_or_None_if_offline, metadata).
        """
        if tracker is not None:
            tracker.check_budget()

        status = self.get_status()
        if status.active_provider == "local_heuristic":
            return None, {"provider": "local_heuristic", "reason": status.guidance}

        model = status.active_model
        kwargs: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if status.active_provider == "openai":
            os.environ["OPENAI_API_KEY"] = self.config.openai_api_key or ""
        elif status.active_provider == "groq":
            os.environ["GROQ_API_KEY"] = self.config.groq_api_key or ""
        elif status.active_provider == "ollama":
            kwargs["api_base"] = self.config.ollama_base_url

        try:
            import litellm

            litellm.suppress_debug_info = True
            response = litellm.completion(**kwargs)
            content = response.choices[0].message.content or ""

            usage = getattr(response, "usage", None)
            p_tok = getattr(usage, "prompt_tokens", 0) or 0
            c_tok = getattr(usage, "completion_tokens", 0) or 0

            # Estimate cost if litellm completion_cost is available
            cost = 0.0
            if status.active_provider in ("openai", "groq"):
                try:
                    cost = float(litellm.completion_cost(completion_response=response) or 0.0)
                except Exception:
                    # Approximate fallback pricing ($0.15/1M in, $0.60/1M out)
                    cost = (p_tok * 0.15 + c_tok * 0.60) / 1_000_000.0

            if tracker is not None:
                tracker.record_usage(p_tok, c_tok, cost)

            return content, {
                "provider": status.active_provider,
                "model": model,
                "prompt_tokens": p_tok,
                "completion_tokens": c_tok,
                "cost_usd": cost,
            }
        except Exception as e:
            return None, {
                "provider": "local_heuristic",
                "error": str(e),
                "reason": f"LLM call failed ({e}); degrading gracefully to local security engine.",
            }
