"""Active non-destructive parameter reflection and input encoding auditor."""

import html
import re
import uuid
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse
import httpx
from sensei.tools.base import BaseToolAdapter
from sensei.tools.schemas import ToolCategory, ToolFinding, ToolInfo, ToolOutput


class ReflectionAuditAdapter(BaseToolAdapter):
    """Audits input parameters for raw reflection, missing HTML encoding, and open redirect risks."""

    COMMON_TEST_PARAMS = ["q", "search", "query", "id", "keyword", "redirect", "url", "next"]

    def __init__(self):
        info = ToolInfo(
            name="reflection_audit",
            display_name="Sensei Parameter Reflection & DAST Auditor",
            description="Safely tests URL parameters and forms using inert canary tokens to verify whether inputs are properly encoded or reflected unescaped.",
            category=ToolCategory.WEB_SECURITY,
            version="1.0.0",
            input_schema={
                "target": {"type": "string", "description": "Target URL to assess (e.g. https://example.com/search?q=test)"},
                "params": {"type": "string", "default": "", "description": "Comma-separated parameter names to audit (optional)"},
            },
            output_schema={"findings": "List of discovered reflection and encoding weaknesses"},
            required_permissions="LOW",
            execution_method="native_adapter",
            timeout_seconds=45,
            is_available=True,
            install_guide="Built into Sensei. No external dependencies required.",
        )
        super().__init__(info)

    def check_availability(self) -> bool:
        return True

    def validate_input(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        target = input_data.get("target")
        if not target or not isinstance(target, str):
            raise ValueError("Target URL must be provided.")
        target = target.strip()
        if not (target.startswith("http://") or target.startswith("https://")):
            target = f"https://{target}"
        parsed = urlparse(target)
        if not parsed.netloc:
            raise ValueError(f"Invalid URL: {target}")

        params = input_data.get("params", "")
        return {"target": target, "params": str(params)}

    def _run_internal(self, input_data: Dict[str, Any], timeout: int) -> ToolOutput:
        target = input_data["target"]
        parsed_target = urlparse(target)
        is_local = (parsed_target.hostname or "").lower() in ("localhost", "127.0.0.1", "::1")

        existing_params = parse_qs(parsed_target.query, keep_blank_values=True)
        custom_params = [p.strip() for p in input_data.get("params", "").split(",") if p.strip()]

        # Combine existing URL parameters and top common endpoints
        params_to_test = list(existing_params.keys())
        if custom_params:
            for cp in custom_params:
                if cp not in params_to_test:
                    params_to_test.append(cp)
        elif not params_to_test:
            params_to_test = list(self.COMMON_TEST_PARAMS[:5])

        findings: List[ToolFinding] = []
        logs: List[str] = [f"Starting non-destructive parameter reflection audit on {target}..."]

        client = httpx.Client(
            timeout=float(timeout),
            verify=False,
            follow_redirects=False,
            trust_env=not is_local,
            headers={"User-Agent": "Sensei-Security-Engineer/0.1.0 (Authorized Reflection Audit)"},
        )

        try:
            for param in params_to_test:
                # 1. Benign canary token to verify if the parameter is reflected at all
                canary_id = uuid.uuid4().hex[:6]
                canary = f"sensei_canary_{canary_id}"
                probe_special = f"{canary}'\"><s_tag>"

                # Build query dictionary
                q_dict = {k: v[0] if isinstance(v, list) and v else "" for k, v in existing_params.items()}
                q_dict[param] = probe_special

                parts = list(parsed_target)
                parts[4] = urlencode(q_dict)
                probe_url = urlunparse(parts)

                try:
                    resp = client.get(probe_url, timeout=6.0)
                except Exception as ex:
                    logs.append(f"Request failed for param '{param}': {ex}")
                    continue

                body = resp.text or ""

                # Check if canary reflected in response
                if canary in body:
                    # Check whether the special characters were reflected verbatim (unescaped)
                    raw_unescaped = f"{canary}'\"><s_tag>"
                    escaped_expected = f"{canary}&#39;&quot;&lt;s_tag&gt;"
                    entity_escaped = f"&lt;s_tag&gt;" in body or f"&amp;lt;s_tag" in body

                    context_snippet = self._extract_context(body, canary)

                    if raw_unescaped in body and not entity_escaped:
                        # Raw unencoded HTML tag reflection detected!
                        findings.append(
                            ToolFinding(
                                finding_id=f"SEC-INJECTION-UNENCODED-PARAM-{param.upper()}",
                                title=f"Unencoded Parameter Reflection in Response (Param: '{param}')",
                                description=(
                                    f"The parameter '{param}' was submitted with inert HTML test characters and was "
                                    f"reflected into the response body verbatim without HTML entity encoding. "
                                    f"This represents an active input reflection sink that could lead to Cross-Site Scripting (XSS)."
                                ),
                                severity="HIGH",
                                affected_asset=f"{target} (Param: {param})",
                                evidence=f"Injected probe: {raw_unescaped}\nObserved context in response:\n{context_snippet}",
                                reproduction=f"curl -k \"{probe_url}\"",
                                remediation=(
                                    f"Ensure all user-supplied input for parameter '{param}' is contextually encoded "
                                    f"(e.g., HTML entity encoding, React JSX data binding) before being rendered into the DOM."
                                ),
                                confidence="CONFIRMED",
                                references=[
                                    "https://owasp.org/www-community/attacks/xss/",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                                ],
                            )
                        )
                        logs.append(f"[CONFIRMED] Parameter '{param}' reflects unencoded HTML characters!")

                    elif canary in body:
                        # Reflected, but properly encoded (Good defensive behavior, informational observation)
                        findings.append(
                            ToolFinding(
                                finding_id=f"SEC-INFO-PARAM-REFLECTED-ENCODED-{param.upper()}",
                                title=f"Parameter '{param}' Reflected with Encoding",
                                description=(
                                    f"The parameter '{param}' is reflected in the application response, but HTML meta-characters "
                                    f"were properly escaped (e.g. &lt; / &gt;). This demonstrates defensive encoding in place."
                                ),
                                severity="INFORMATIONAL",
                                affected_asset=f"{target} (Param: {param})",
                                evidence=f"Probe reflected safely in context:\n{context_snippet}",
                                reproduction=f"curl -k \"{probe_url}\"",
                                remediation="Maintain strict context-aware encoding across all page templates.",
                                confidence="CONFIRMED",
                            )
                        )
                        logs.append(f"[INFO] Parameter '{param}' reflected safely with encoding.")

                # Open Redirect check for navigation parameters
                if param.lower() in ("redirect", "url", "next", "return", "return_to", "dest", "target"):
                    test_redirect_host = "https://example.com"
                    q_dict[param] = test_redirect_host
                    parts[4] = urlencode(q_dict)
                    redir_url = urlunparse(parts)

                    try:
                        redir_resp = client.get(redir_url, timeout=5.0)
                        loc = redir_resp.headers.get("location", "")
                        if redir_resp.status_code in (301, 302, 303, 307, 308) and test_redirect_host in loc:
                            findings.append(
                                ToolFinding(
                                    finding_id=f"SEC-REDIRECT-OPEN-{param.upper()}",
                                    title=f"Potential Open Redirect via Parameter '{param}'",
                                    description=(
                                        f"The application responded with HTTP {redir_resp.status_code} redirecting directly to "
                                        f"an untrusted external location supplied in parameter '{param}'."
                                    ),
                                    severity="MEDIUM",
                                    affected_asset=f"{target} (Param: {param})",
                                    evidence=f"HTTP {redir_resp.status_code} -> Location: {loc}",
                                    reproduction=f"curl -k -I \"{redir_url}\"",
                                    remediation="Validate redirection targets against a strict server-side allowlist of internal relative paths.",
                                    confidence="CONFIRMED",
                                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
                                )
                            )
                            logs.append(f"[CONFIRMED] Open redirect observed on '{param}'.")
                    except Exception:
                        pass

        finally:
            client.close()

        logs.append(f"Reflection audit finished with {len(findings)} finding(s).")
        raw_output = "\n".join(logs) + "\n\n" + "\n".join([f"[{f.severity}] {f.title} ({f.finding_id})" for f in findings])

        return ToolOutput(
            tool_name="reflection_audit",
            success=True,
            exit_code=0,
            raw_output=raw_output,
            findings=findings,
            structured_data={"tested_params_count": len(params_to_test), "findings_count": len(findings)},
        )

    def _extract_context(self, body: str, token: str, window: int = 140) -> str:
        """Extract a snippet of text surrounding the canary."""
        idx = body.find(token)
        if idx == -1:
            return ""
        start = max(0, idx - window)
        end = min(len(body), idx + len(token) + window)
        return body[start:end].strip()
