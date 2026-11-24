# AI Application Security Skill

## When to Use
Use when assessing LLM-integrated applications, chatbots, agentic workflows, and RAG pipelines for AI-specific attack vectors.

## Objective
Detect OWASP Top 10 for LLM Applications weaknesses such as indirect prompt injection, data leakage, insecure output handling, and excessive agency.

## Required Input
- `ai_endpoint`: Chat or completion endpoint URL.
- `context`: Description of the AI agent or chatbot capabilities.

## Available Tools
- `http_audit`: HTTP transport and API endpoint checks.
- `ai_security_scanner`: Heuristic prompt injection test suites.

## Execution Methodology
1. Map LLM inputs, tools, and execution capabilities.
2. Probe for system prompt leakage.
3. Assess guardrails against role override and jailbreaking attempts.
4. Inspect model output rendering for stored XSS or unsanitized markdown execution.

## Validation Criteria
- Confirmed output containing system prompt secrets or execution of unauthorized tool calls.

## Safety Restrictions
- Prohibited: Generating harmful, offensive, or destructive payloads.
- All testing strictly scoped to model boundary and authorization enforcement.

## Expected Output
- LLM vulnerability summary, guardrail resilience score, and defense-in-depth recommendations.
