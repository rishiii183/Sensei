"""Client-side DOM security analyzer inspecting scripts, sinks, and postMessage handlers."""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse
import httpx
from sensei.tools.base import BaseToolAdapter
from sensei.tools.schemas import ToolCategory, ToolFinding, ToolInfo, ToolOutput


class DomAuditAdapter(BaseToolAdapter):
    """Audits client-side HTML and scripts for dangerous DOM sinks and insecure postMessage patterns."""

    def __init__(self):
        info = ToolInfo(
            name="dom_audit",
            display_name="Sensei DOM & Client Security Analyzer",
            description="Analyzes rendered HTML, DOM sinks (innerHTML, eval, document.write), postMessage handlers, and client-side storage practices.",
            category=ToolCategory.WEB_SECURITY,
            version="1.0.0",
            input_schema={"target": {"type": "string", "description": "Target webpage URL to audit"}},
            output_schema={"findings": "List of discovered client-side and DOM security weaknesses"},
            required_permissions="LOW",
            execution_method="native_adapter",
            timeout_seconds=30,
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
        return {"target": target}

    def _run_internal(self, input_data: Dict[str, Any], timeout: int) -> ToolOutput:
        target = input_data["target"]
        parsed_target = urlparse(target)
        is_local = (parsed_target.hostname or "").lower() in ("localhost", "127.0.0.1", "::1")

        findings: List[ToolFinding] = []
        logs: List[str] = [f"Starting DOM & client-side security analysis on {target}..."]

        client = httpx.Client(
            timeout=float(timeout),
            verify=False,
            follow_redirects=True,
            trust_env=not is_local,
            headers={"User-Agent": "Sensei-Security-Engineer/0.1.0 (Authorized DOM Audit)"},
        )

        try:
            resp = client.get(target)
            content = resp.text or ""
            logs.append(f"Fetched page: HTTP {resp.status_code} ({len(content)} bytes)")

            # 1. Dangerous DOM Sinks Inspection
            sink_patterns = [
                (r"(\.innerHTML\s*=)", "Dangerous DOM Sink: innerHTML Assignment", "MEDIUM"),
                (r"(\.outerHTML\s*=)", "Dangerous DOM Sink: outerHTML Assignment", "MEDIUM"),
                (r"(document\.write(?:ln)?\s*\()", "Dangerous DOM Sink: document.write()", "HIGH"),
                (r"(dangerouslySetInnerHTML\s*=)", "React dangerouslySetInnerHTML Usage", "MEDIUM"),
                (r"(\beval\s*\([^\)]+\))", "Dangerous JavaScript Execution via eval()", "HIGH"),
            ]

            for regex, title, severity in sink_patterns:
                matches = list(re.finditer(regex, content, re.IGNORECASE))
                if matches:
                    snippets = []
                    for m in matches[:3]:
                        start = max(0, m.start() - 40)
                        end = min(len(content), m.end() + 60)
                        snippets.append(content[start:end].strip())

                    findings.append(
                        ToolFinding(
                            finding_id=f"SEC-DOM-SINK-{matches[0].group(1).split('(')[0].replace('.', '_').replace('=', '').strip().upper()}",
                            title=title,
                            description=(
                                f"Identified {len(matches)} instance(s) of '{matches[0].group(1).strip()}' in client-side code. "
                                f"Direct DOM manipulation sinks can lead to client-side DOM XSS if populated with unvalidated user input."
                            ),
                            severity=severity,
                            affected_asset=target,
                            evidence="\n---\n".join(snippets),
                            reproduction=f"curl -s \"{target}\" | grep -E \"{matches[0].group(1).strip()}\"",
                            remediation=(
                                "Replace direct DOM injection sinks with safe text-node assignments (e.g. textContent), "
                                "use standard framework JSX bindings, or sanitize strings using DOMPurify before rendering."
                            ),
                            confidence="CONFIRMED",
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"],
                        )
                    )
                    logs.append(f"[CONFIRMED] {title} identified ({len(matches)} match(es)).")

            # 2. Insecure postMessage Event Listeners
            if 'addEventListener("message"' in content or "addEventListener('message'" in content:
                # Check whether origin validation exists near the handler
                msg_match = re.search(r"addEventListener\s*\(\s*['\"]message['\"].*?function\s*\(([a-zA-Z0-9_]+)\)", content, re.DOTALL)
                origin_checked = False
                if msg_match:
                    evt_var = msg_match.group(1)
                    # Look for evt.origin check within next 300 characters
                    start = msg_match.end()
                    block = content[start:start+350]
                    if f"{evt_var}.origin" in block:
                        origin_checked = True

                if not origin_checked:
                    findings.append(
                        ToolFinding(
                            finding_id="SEC-DOM-POSTMESSAGE-NO-ORIGIN",
                            title="Cross-Window postMessage Listener Lacks Origin Check",
                            description=(
                                "The webpage registers a window message event listener without validating the event.origin property. "
                                "Any malicious cross-origin page can iframe or open this window and post crafted message payloads."
                            ),
                            severity="MEDIUM",
                            affected_asset=target,
                            evidence="addEventListener('message', ...) detected without adjacent event.origin verification.",
                            reproduction=f"Inspect window message listener in {target}",
                            remediation="Always verify 'event.origin === \"https://your-trusted-domain.com\"' inside window message handlers before processing data.",
                            confidence="HIGH",
                            references=["https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns"],
                        )
                    )
                    logs.append("[CONFIRMED] Insecure postMessage listener detected.")

            # 3. Inline Script Exposure
            inline_scripts = list(re.finditer(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", content, re.DOTALL | re.IGNORECASE))
            if len(inline_scripts) >= 2:
                has_nonce = any("nonce=" in m.group(0).lower() for m in inline_scripts)
                if not has_nonce:
                    findings.append(
                        ToolFinding(
                            finding_id="SEC-DOM-INLINE-SCRIPTS-EXPOSED",
                            title=f"Multiple Un-Nonces Inline Scripts ({len(inline_scripts)} blocks)",
                            description=(
                                f"Discovered {len(inline_scripts)} un-nonced inline <script> block(s). "
                                f"Without CSP script-src nonces or hashes, the application cannot effectively protect against injected script payloads."
                            ),
                            severity="LOW",
                            affected_asset=target,
                            evidence=f"Discovered {len(inline_scripts)} inline script tags lacking 'nonce' or 'integrity' attributes.",
                            reproduction=f"curl -s \"{target}\" | grep -c '<script>'",
                            remediation="Migrate inline scripts to external bundle files or attach cryptographic nonces verified by Content-Security-Policy.",
                            confidence="CONFIRMED",
                            references=["https://content-security-policy.com/nonce/"],
                        )
                    )
                    logs.append(f"[INFO] Discovered {len(inline_scripts)} un-nonced inline scripts.")

        except Exception as ex:
            logs.append(f"DOM audit encountered an error: {ex}")
            return ToolOutput(
                tool_name="dom_audit",
                success=False,
                exit_code=1,
                raw_output="\n".join(logs),
                findings=findings,
                error_message=str(ex),
            )
        finally:
            client.close()

        logs.append(f"DOM audit completed with {len(findings)} observation(s).")
        raw_output = "\n".join(logs) + "\n\n" + "\n".join([f"[{f.severity}] {f.title} ({f.finding_id})" for f in findings])

        return ToolOutput(
            tool_name="dom_audit",
            success=True,
            exit_code=0,
            raw_output=raw_output,
            findings=findings,
            structured_data={"findings_count": len(findings)},
        )
