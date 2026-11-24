# Sensei — Autonomous AI Security Engineer

**Test. Understand. Secure.**

Sensei is an open-source, CLI-first autonomous security engineering assistant designed to accept natural-language instructions, verify target scope authorization, generate structured execution plans, execute non-destructive security tools, validate findings with concrete technical evidence, and teach developers the core security principles behind discovered issues.

---

## Table of Contents

- [Overview](#overview)
- [Key Architectural Highlights](#key-architectural-highlights)
- [System Architecture](#system-architecture)
- [Operating Modes](#operating-modes)
- [Safety and Permission Model](#safety-and-permission-model)
- [Tool Ecosystem](#tool-ecosystem)
- [Skills Subsystem](#skills-subsystem)
- [Persistence and Memory](#persistence-and-memory)
- [Reporting Engine](#reporting-engine)
- [Installation and Setup](#installation-and-setup)
- [Usage Guide](#usage-guide)
  - [Interactive Mode](#interactive-mode)
  - [Command Reference](#command-reference)
  - [Non-Interactive CLI Execution](#non-interactive-cli-execution)
- [Configuration and Budgets](#configuration-and-budgets)
- [Testing](#testing)
- [Contributing and Security Policy](#contributing-and-security-policy)

---

## Overview

Unlike conventional conversational chatbots that produce unverified advice or hallucinate security bugs, Sensei functions as an active agentic engine:

1. **Understands Intent**: Parses natural-language user objectives (e.g., *"Perform a security assessment of my authorized test website"*).
2. **Enforces Strict Scope**: Validates that candidate targets match explicit user authorization in the Target Scope Registry before executing network requests.
3. **Plans Non-Destructive Actions**: Synthesizes structured execution steps selecting only registered, non-destructive tools.
4. **Applies Guardrails & Rate Limits**: Restricts execution to authorized permission levels while throttling all tool actions with a token-bucket rate limiter.
5. **Validates Technical Evidence**: Filters false positives by demanding reproducible HTTP headers, status codes, or tool outputs, categorizing findings into `CONFIRMED`, `POTENTIAL`, and `INFORMATIONAL`.
6. **Acts as a Security Mentor**: Explains underlying mechanics (CSP, CORS, Clickjacking, MIME sniffing, Information Disclosure) and provides actionable remediation guidance.

---

## Key Architectural Highlights

- **CLI-First Experience**: Built using Typer, Rich terminal tables and cards, and `prompt_toolkit` with command completion and session history.
- **LangGraph Orchestration**: Central StateGraph managing scope validation, planning, permission gates, specialist workflows, result verification, and report synthesis.
- **Provider-Independent LLM Abstraction**: Powered by LiteLLM supporting OpenAI (`gpt-4o-mini`), Groq (`llama-3.3-70b-versatile`), local Ollama (`llama3.2`), or an offline deterministic heuristic security engine.
- **Cost & Token Budget Controls**: Enforces per-scan token and cost limits, truncating tool output to prevent context exhaustion.
- **Zero-Dependency Native Security Scanner**: Ships with `http_audit`, an out-of-the-box non-destructive HTTP/TLS auditor requiring no external binaries.
- **Modular Specialist Agents**: Controlled LangGraph nodes for Reconnaissance, Web Security, API Security, AI Application Security, and Security Mentorship.
- **Persistent Local Memory**: SQLite persistence via SQLAlchemy tracking sessions, targets, plans, tool outputs, findings, and reports with full session resumption (`/resume`).

---

## System Architecture

```text
Sensei Orchestrator
|
|-- Target Scope Registry & Guardrails (URL, IP, CIDR validation)
|-- Planning Engine (LiteLLM or Deterministic Security Planner)
|-- Permission Manager (OBSERVE, COPILOT, AUTOPILOT)
|-- Execution Manager & Rate Limiter (Token-Bucket Pacing)
|-- Tool Registry & Adapters
|    |-- http_audit (Native Python HTTP/TLS auditor)
|    |-- nuclei (Non-destructive template scanner)
|    |-- nmap (Safe port & service discovery)
|    |-- semgrep (SAST code analysis)
|    |-- gitleaks (Secret & token detection)
|    |-- trivy (Vulnerability & container inspection)
|-- Specialist Workflows (LangGraph Nodes)
|    |-- Recon Specialist
|    |-- Web Security Specialist
|    |-- API Security Specialist
|    |-- AI Security Specialist
|    |-- Security Mentor
|-- Result Validator (Evidence verification & deduplication)
|-- Reporting Engine (Terminal, Markdown, JSON, HTML)
+-- SQLite Persistence Layer (Sessions, Plans, Findings, Audits)
```

---

## Operating Modes

Sensei enforces three distinct operational security modes:

1. **OBSERVE**:
   - Generates assessment plans and explains proposed actions.
   - Requires explicit manual approval before executing any tool check (except passive safe reads).
2. **COPILOT (Default)**:
   - Automatically executes safe and low-risk verification checks (e.g., passive HTTP header inspection, technology discovery).
   - Pauses and prompts the user for confirmation prior to medium or high-risk active probing.
3. **AUTOPILOT**:
   - Executes predefined, authorized workflows across safe, low, and medium tiers without interrupting.
   - Halts immediately if actions exceed authorized scope boundaries or per-scan budgets.

---

## Safety and Permission Model

Sensei is built specifically for defensive security engineering. The following operations are **permanently restricted and blocked across all operating modes**:

- Targets outside the registered and authorized scope
- Destructive operations (e.g., `DROP TABLE`, filesystem wiping)
- Denial-of-Service (DoS) and volumetric flooding
- Unauthorized exploitation and arbitrary shell command execution
- Credential stuffing and brute-forcing
- Data exfiltration and persistence/backdoor mechanisms

Additionally, all untrusted external content (scanned webpage bodies, server responses, tool outputs) is sanitized and enclosed within `<UNTRUSTED_EXTERNAL_DATA>` blocks to prevent indirect prompt injection attacks against the agent.

---

## Tool Ecosystem

Sensei includes a dynamic tool registry where adapters expose schemas, risk levels, rate limits, and availability checks:

| Tool Identifier | Category | Execution Method | Default Status | Capabilities |
| :--- | :--- | :--- | :--- | :--- |
| `http_audit` | Web Security | Native Python (`httpx`) | Built-in (Always Available) | Audits CSP, HSTS, X-Frame-Options, MIME sniffing, cookie security flags, banner disclosures, sensitive endpoints (`/.git/HEAD`, `/.env`, `/robots.txt`). |
| `nuclei` | Web Security | CLI Subprocess | Checked via PATH | Runs ProjectDiscovery Nuclei with safe, non-destructive template sets (`cve`, `misconfig`, `tech`) under strict rate limits. |
| `nmap` | Network Security | CLI Subprocess | Checked via PATH | Non-intrusive port and service discovery (`-sV --version-light -Pn`) on standard HTTP/API ports. |
| `semgrep` | Code Security | CLI Subprocess | Checked via PATH | Static application security testing (SAST) identifying security bugs in source files. |
| `gitleaks` | Code Security | CLI Subprocess | Checked via PATH | Audits repositories and local directories for hardcoded API keys, tokens, and credentials. |
| `trivy` | Infrastructure | CLI Subprocess | Checked via PATH | Scans dependencies, container files, and filesystems for known CVEs. |

Run `sensei doctor` at any time to verify installed tool binaries and environment readiness.

---

## Skills Subsystem

Methodologies are organized into structured, modular Markdown guides in `skills/*/SKILL.md`:

- `skills/reconnaissance/SKILL.md`: Attack surface mapping and passive service discovery.
- `skills/web-pentesting/SKILL.md`: OWASP Top 10 web posture and misconfiguration checks.
- `skills/api-security/SKILL.md`: REST and GraphQL endpoint audits, CORS, and exposure checks.
- `skills/ai-security/SKILL.md`: LLM application security and guardrail resilience.
- `skills/prompt-injection/SKILL.md`: Non-destructive canary injection and system prompt preservation.
- `skills/vulnerability-validation/SKILL.md`: Corroborating evidence and eliminating false positives.
- `skills/security-reporting/SKILL.md`: Evidence-based report generation and developer education.

---

## Persistence and Memory

Sensei uses SQLite (`sensei.db`) managed via SQLAlchemy models to retain historical context:

- **Sessions**: Tracks start time, operating mode, token usage, cost accumulation, and state.
- **Target Scopes**: Records authorized targets, authorization timestamps, and notes.
- **Plans & Steps**: Retains generated assessment plans, execution status, and tool inputs.
- **Tool Executions**: Records duration, exit codes, raw outputs, and truncation status.
- **Findings**: Stores normalized vulnerabilities, severities, evidence strings, and reproduction steps.
- **Audit Logs**: Maintains an immutable timeline of security events, scope checks, approvals, and blocks.

You can close the terminal at any time and resume using `/resume <session_id>` or `sensei --resume <session_id>`.

---

## Reporting Engine

Reports can be generated on-demand during an interactive session or upon CLI completion:

- **Terminal**: Formatted tables, severity badges, and detailed evidence cards rendered with Rich.
- **Markdown (`reports/*.md`)**: Clean documentation suitable for pull requests, GitHub issues, or issue trackers.
- **JSON (`reports/*.json`)**: Structured, machine-readable output for automated CI/CD pipelines.
- **HTML (`reports/*.html`)**: Self-contained, XSS-escaped HTML report for stakeholder presentations.

Every finding provides:
- Finding ID (e.g., `SEC-HEADER-CSP-MISSING`)
- Vulnerability Title & Severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`)
- Validation Status (`CONFIRMED`, `POTENTIAL`, `INFORMATIONAL`)
- Affected Asset
- Verifiable Evidence Snippet
- Reproduction Command (e.g., `curl -I ...`)
- Potential Impact Assessment
- Actionable Remediation Guidance & References

---

## Installation and Setup

### Prerequisites

- **Python**: Version 3.12 or newer
- **Package Manager**: [uv](https://github.com/astral-sh/uv) (recommended) or standard `pip`

### 1. Clone the Repository

```bash
git clone https://github.com/rishiii183/Sensei.git
cd Sensei
```

### 2. Install Dependencies

Using `uv`:
```bash
uv sync
```

Alternatively using standard `pip`:
```bash
python -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
pip install -e .
```

### 3. Environment Configuration

Copy the example environment template:
```bash
cp .env.example .env
```

Edit `.env` to configure your preferred LLM provider (optional):
```ini
# OpenAI Configuration (Default cloud model)
OPENAI_API_KEY=your-openai-api-key
DEFAULT_MODEL=openai/gpt-4o-mini

# Groq Configuration (Ultra-fast cloud inference)
GROQ_API_KEY=your-groq-api-key
GROQ_MODEL=groq/llama-3.3-70b-versatile

# Ollama Configuration (Local, private LLM fallback)
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=ollama/llama3.2

# Operational Settings
SENSEI_MODE=COPILOT
PER_SCAN_TOKEN_BUDGET=150000
PER_SCAN_COST_BUDGET=1.50
MAX_TOOL_OUTPUT_CHARS=3000
TOOL_RATE_LIMIT=2.0
DATABASE_URL=sqlite:///sensei.db
```

*Note: If no API key is provided and Ollama is offline, Sensei automatically switches to its built-in deterministic security planning engine, ensuring complete functionality without external dependencies.*

### 4. Verify Diagnostics

```bash
uv run sensei doctor
```

---

## Usage Guide

### Interactive Mode

Launch the interactive Sensei shell:
```bash
uv run sensei
```

```text
+-----------------------------------------------------------------------------+
|  SENSEI                                                                     |
|  Autonomous AI Security Engineer                                            |
|  Test. Understand. Secure.                                                  |
|  Version: 0.1.0  |  Mode: COPILOT  |  LLM: groq/llama-3.3-70b-versatile    |
+-----------------------------------------------------------------------------+
Welcome back.
What would you like to investigate? (Type /help for commands)

sensei > Perform a security assessment of http://localhost:3000
```

### Command Reference

| Command | Arguments | Description |
| :--- | :--- | :--- |
| `/help` | - | Display all available commands and syntax. |
| `/status` | - | Show current session ID, mode, active target, LLM provider, and token budget. |
| `/target` | `<url_or_host>` | Set active target and prompt for scope authorization if unregistered. |
| `/scope` | `list` | List all registered target scopes and authorization statuses. |
| `/scope` | `authorize <target>` | Add and authorize a target scope explicitly. |
| `/scope` | `remove <target>` | Remove a target from the authorized scope registry. |
| `/scan` | `[target]` | Initiate an assessment against the active or specified target. |
| `/tools` | - | List all security tool adapters and their local installation statuses. |
| `/findings` | - | Display all validated findings discovered in the active session. |
| `/report` | `[terminal\|markdown\|json\|html]` | Export session findings in the specified format. |
| `/permissions`| `[OBSERVE\|COPILOT\|AUTOPILOT]` | Inspect or switch the current operating mode. |
| `/approve` | `<request_id>` | Approve a pending gated action. |
| `/deny` | `<request_id>` | Deny a pending gated action. |
| `/plan` | - | Display the active structured assessment plan. |
| `/skills` | - | List all loaded Markdown security methodology skills. |
| `/agents` | - | View specialist agent nodes and their permitted tool sets. |
| `/memory` | - | Display SQLite persistent storage metrics. |
| `/history` | - | List previous assessment sessions. |
| `/resume` | `<session_id>` | Resume an earlier assessment session. |
| `/clear` | - | Clear the terminal window. |
| `/exit` | - | Save session state and exit. |

### Non-Interactive CLI Execution

Sensei supports direct, non-interactive execution for scripting and CI/CD pipelines:

```bash
# Run assessment against an authorized test environment with markdown export
uv run sensei run "Perform a security assessment of my authorized test website" \
  --target http://localhost:3000 \
  --authorize \
  --yes \
  --report-format markdown
```

Command-line utilities:
```bash
# List all registered security tools
uv run sensei tools list

# Check environment health and tool availability
uv run sensei doctor

# View past assessment history
uv run sensei history
```

---

## Configuration and Budgets

Sensei provides safety and resource limits configurable in `.env` or `configs/default.yaml`:

- `PER_SCAN_TOKEN_BUDGET`: Cumulative token budget ceiling (default: `150000`). The agent halts and requests user override before exceeding this limit.
- `PER_SCAN_COST_BUDGET`: Dollar-denominated expenditure cap (default: `$1.50`).
- `MAX_TOOL_OUTPUT_CHARS`: Output truncation limit (default: `3000` characters). Preserves head and tail context while discarding repetitive intermediate lines to maintain LLM context window efficiency.
- `TOOL_RATE_LIMIT`: Global and per-target execution pacing in requests per second (default: `2.0` rps).

---

## Testing

Sensei comes with an automated unit and integration test suite covering scope validation, permission policies, sanitization, rate-limiting, persistence, tool adapters, and LangGraph workflows:

```bash
# Run the complete test suite
uv run pytest -v
```

All tests execute against local mock servers and in-memory SQLite instances, requiring no external network connectivity or live credentials.

---

## Contributing and Security Policy

Sensei is built exclusively for authorized testing, educational demonstrations, and defensive security engineering.

- When contributing new tool adapters, ensure they inherit from `BaseToolAdapter`, implement strict argument validation, and never use `shell=True`.
- Destructive testing techniques or unauthorized attack modules will not be accepted.
- Report security issues or vulnerabilities responsibly via GitHub Issues.
