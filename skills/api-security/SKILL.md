# API Security Assessment Skill

## When to Use
Use when auditing REST, GraphQL, or JSON APIs for authorization gaps, mass assignment, unauthenticated endpoints, and rate limiting.

## Objective
Detect OWASP API Security Top 10 vulnerabilities including Broken Object Level Authorization (BOLA), excessive data exposure, and missing security controls.

## Required Input
- `api_base_url`: Base URL of the API.
- `schema_url`: OpenAPI/Swagger or GraphQL schema location if available.

## Available Tools
- `http_audit`: Non-destructive endpoint probing and header checking.
- `nuclei`: API-specific misconfiguration templates.

## Execution Methodology
1. Locate API documentation endpoints (`/swagger.json`, `/api-docs`, `/openapi.json`).
2. Verify authentication enforcement across discovered sensitive paths.
3. Test for excessive data exposure in returned JSON payloads.
4. Verify HTTP methods and CORS origin handling.

## Validation Criteria
- Confirm whether unauthenticated requests receive 401/403 or 200 OK with sensitive data.

## Safety Restrictions
- Prohibited: State-modifying destructive requests (`DELETE /users/all`).
- Prohibited: DoS through mass endpoint requests.

## Expected Output
- API security audit matrix with endpoint status, authorization posture, and remediation guidance.
