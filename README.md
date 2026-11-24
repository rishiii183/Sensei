# Sensei — Autonomous AI Security Engineer

**Test. Understand. Secure.**

Sensei is a CLI-first autonomous AI security engineering assistant designed to accept natural-language instructions, verify target authorization and scope boundaries, plan structured non-destructive assessments, execute isolated security tools, validate findings with concrete evidence, and teach the user the underlying security concepts.

## Key Features

- **Interactive CLI (`sensei`)**: Built with Typer, Rich, and `prompt_toolkit` with command auto-completion, session persistence, and clean non-cluttered terminal output.
- **Scope & Permission Guardrails**: Strict target scope registry and three operating modes (`OBSERVE`, defaulting to `COPILOT`, and bounded `AUTOPILOT`). Strictly prohibits DoS, destructive payloads, credential theft, and out-of-scope targets.
- **LangGraph Orchestration**: Central `StateGraph` coordinating scope verification, structured planning, permission gates, specialist workflows (`recon`, `web_security`, `api_security`, `ai_security`, `mentor`), validation, and reporting.
- **Provider-Independent LLM (LiteLLM)**: Uses `openai/gpt-4o-mini` by default via `OPENAI_API_KEY`, degrades gracefully to local Ollama (`ollama/llama3.2`) or offline deterministic security mode when no key is configured, and enforces per-scan token/cost budgets.
- **Dynamic Tool Ecosystem**: Rate-limited, timeout-enforced direct adapters including built-in `http_audit`, ProjectDiscovery `nuclei` (non-destructive template set), `nmap`, `semgrep`, `trivy`, and `gitleaks`.
- **SQLite Persistence**: Saves sessions, scopes, plans, tool execution history, validated findings, and exported reports (`sensei.db`) with `/resume` support.
- **Evidence-Based Reporting**: Generates Terminal, Markdown, JSON, and HTML reports separating `CONFIRMED`, `POTENTIAL`, and `INFORMATIONAL` findings.

## Quick Start

```bash
# Install dependencies
uv sync

# Configure environment (optional OPENAI_API_KEY; falls back cleanly to Ollama or offline engine)
cp .env.example .env

# Check environment & tool readiness
uv run sensei doctor

# List registered security tools
uv run sensei tools list

# Start interactive session
uv run sensei
```

## Non-Interactive Assessment Example (OWASP Juice Shop)

```bash
# 1. Start local authorized test target (e.g., OWASP Juice Shop on port 3000)
# docker run --rm -p 3000:3000 bkimminich/juice-shop

# 2. Run authorized assessment with Sensei
uv run sensei run "Perform a security assessment of my authorized test website." --target http://localhost:3000 --authorize --report-format markdown
```

## Interactive Commands

- `/help`, `/status`, `/clear`, `/exit`
- `/target <url>`, `/scope [list|authorize|remove]`
- `/scan [target]`, `/tools`, `/findings`, `/report [terminal|markdown|json|html]`
- `/permissions [OBSERVE|COPILOT|AUTOPILOT]`, `/approve <id>`, `/deny <id>`
- `/plan`, `/agents`, `/skills`, `/memory`, `/history`, `/sessions`, `/resume <id>`

## Running Tests

```bash
uv run pytest
```
