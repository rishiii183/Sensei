# Security Reporting & Mentor Explanation Skill

## When to Use
Use at the completion of an authorized assessment to synthesize findings into structured reports and clear educational guidance.

## Objective
Deliver evidence-based, actionable security reports in Terminal, Markdown, JSON, and HTML formats, paired with clear explanations of why each issue matters and how to fix it.

## Required Input
- `validated_findings`: Deduplicated findings with evidence and validation status.
- `target`: Assessed target and scope record.
- `session_summary`: Token usage, duration, and executed tools.

## Available Tools
- `reporting_generator`: Multi-format report exporter.
- `security_mentor`: Educational explanation engine.

## Execution Methodology
1. Group findings by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`).
2. Separate `CONFIRMED` findings from `POTENTIAL` and `INFORMATIONAL` observations.
3. Attach exact reproduction commands, observed evidence, impact, and remediation steps to every finding.
4. Generate terminal summary plus Markdown, JSON, and HTML artifacts when requested.
5. Present clear Security Mentor takeaways explaining the underlying security concepts.

## Validation Criteria
- Zero unsubstantiated claims; every finding links directly to captured tool output.

## Safety Restrictions
- Redact sensitive secrets or credentials before persisting reports.

## Expected Output
- Structured `SecurityReport` rendered to terminal and/or saved to `reports/`.
