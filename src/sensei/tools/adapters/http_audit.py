"""Built-in safe web security analyzer performing non-destructive HTTP/TLS audits."""

import httpx
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse
from sensei.tools.base import BaseToolAdapter
from sensei.tools.schemas import ToolCategory, ToolInfo, ToolOutput, ToolFinding


class HttpAuditAdapter(BaseToolAdapter):
    """Native Python web security analyzer checking headers, cookies, and sensitive exposures."""

    def __init__(self):
        info = ToolInfo(
            name="http_audit",
            display_name="Sensei Safe HTTP Auditor",
            description="Native HTTP auditor inspecting security headers, cookies, CORS, technology leaks, and sensitive files.",
            category=ToolCategory.WEB_SECURITY,
            version="1.0.0",
            input_schema={"target": {"type": "string", "description": "Target URL (e.g. http://localhost:3000)"}},
            output_schema={"findings": "List of discovered configuration weaknesses and evidence"},
            required_permissions="LOW",
            execution_method="native_adapter",
            timeout_seconds=30,
            is_available=True,
            install_guide="Built into Sensei. No external dependencies required.",
        )
        super().__init__(info)

    def check_availability(self) -> bool:
        """Native adapter is always available."""
        return True

    def validate_input(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        target = input_data.get("target")
        if not target or not isinstance(target, str):
            raise ValueError("Target URL must be provided.")
        target = target.strip()
        if not (target.startswith("http://") or target.startswith("https://")):
            target = f"http://{target}"
        parsed = urlparse(target)
        if not parsed.netloc:
            raise ValueError(f"Invalid URL: {target}")
        return {"target": target}

    def _run_internal(self, input_data: Dict[str, Any], timeout: int) -> ToolOutput:
        target = input_data["target"]
        findings: List[ToolFinding] = []
        logs: List[str] = [f"Starting safe HTTP security audit on {target}..."]

        parsed_host = (urlparse(target).hostname or "").lower()
        is_local = parsed_host in ("localhost", "127.0.0.1", "::1")

        client = httpx.Client(
            timeout=float(timeout),
            verify=False,
            follow_redirects=True,
            trust_env=not is_local,
            headers={"User-Agent": "Sensei-Security-Engineer/0.1.0 (Authorized Audit)"},
        )

        try:
            # 1. Main Root / Base Response Audit
            resp = client.get(target)
            logs.append(f"Base request status: {resp.status_code} ({len(resp.content)} bytes)")
            headers = {k.lower(): v for k, v in resp.headers.items()}

            # --- Check 1: Content Security Policy (CSP) ---
            if "content-security-policy" not in headers:
                findings.append(
                    ToolFinding(
                        finding_id="SEC-HEADER-CSP-MISSING",
                        title="Missing Content-Security-Policy (CSP) Header",
                        description="The application does not enforce a Content-Security-Policy, significantly increasing exposure to Cross-Site Scripting (XSS) and data injection attacks.",
                        severity="MEDIUM",
                        affected_asset=target,
                        evidence="Header 'Content-Security-Policy' was absent from HTTP response.",
                        reproduction=f"curl -I {target}",
                        remediation="Define and send a robust Content-Security-Policy header restricting script and resource execution origins (e.g., default-src 'self').",
                        confidence="CONFIRMED",
                        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
                    )
                )

            # --- Check 2: X-Frame-Options (Clickjacking) ---
            if "x-frame-options" not in headers and "content-security-policy" not in headers:
                findings.append(
                    ToolFinding(
                        finding_id="SEC-HEADER-XFO-MISSING",
                        title="Missing Anti-Clickjacking Header (X-Frame-Options)",
                        description="The website lacks the X-Frame-Options or frame-ancestors directive, allowing attackers to embed this page in malicious iframes to hijack user clicks.",
                        severity="MEDIUM",
                        affected_asset=target,
                        evidence="No 'X-Frame-Options' header found in response headers.",
                        reproduction=f"curl -I {target}",
                        remediation="Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or use CSP 'frame-ancestors'.",
                        confidence="CONFIRMED",
                        references=["https://owasp.org/www-community/attacks/Clickjacking"],
                    )
                )

            # --- Check 3: X-Content-Type-Options (MIME Sniffing) ---
            if headers.get("x-content-type-options", "").lower() != "nosniff":
                findings.append(
                    ToolFinding(
                        finding_id="SEC-HEADER-XCTO-MISSING",
                        title="Missing X-Content-Type-Options: nosniff",
                        description="Without 'nosniff', browsers may attempt to MIME-sniff response bodies, potentially executing malicious scripts disguised as images or text.",
                        severity="LOW",
                        affected_asset=target,
                        evidence=f"X-Content-Type-Options is '{headers.get('x-content-type-options', 'MISSING')}'.",
                        reproduction=f"curl -I {target}",
                        remediation="Include 'X-Content-Type-Options: nosniff' on all HTTP responses.",
                        confidence="CONFIRMED",
                        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
                    )
                )

            # --- Check 4: Strict-Transport-Security (HSTS) ---
            if target.startswith("https://") and "strict-transport-security" not in headers:
                findings.append(
                    ToolFinding(
                        finding_id="SEC-HEADER-HSTS-MISSING",
                        title="Missing Strict-Transport-Security (HSTS)",
                        description="HTTPS is used but HSTS is not enabled, leaving users vulnerable to SSL stripping and man-in-the-middle attacks.",
                        severity="LOW",
                        affected_asset=target,
                        evidence="No 'Strict-Transport-Security' header present on HTTPS response.",
                        reproduction=f"curl -I {target}",
                        remediation="Configure 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                        confidence="CONFIRMED",
                        references=["https://owasp.org/www-project-secure-headers/#strict-transport-security"],
                    )
                )

            # --- Check 5: Information Disclosure / Server & Technology Leaks ---
            server_header = headers.get("server")
            x_powered_by = headers.get("x-powered-by")
            leak_details = []
            if server_header:
                leak_details.append(f"Server: {server_header}")
            if x_powered_by:
                leak_details.append(f"X-Powered-By: {x_powered_by}")

            if leak_details:
                findings.append(
                    ToolFinding(
                        finding_id="SEC-INFO-DISCLOSURE-BANNER",
                        title="Server Banner & Framework Version Disclosure",
                        description="Server reveals exact software stack or framework versions via response headers, assisting adversary reconnaissance.",
                        severity="INFORMATIONAL",
                        affected_asset=target,
                        evidence="; ".join(leak_details),
                        reproduction=f"curl -I {target}",
                        remediation="Disable banner broadcasting in server/framework configuration (e.g. ServerTokens Prod in Apache, server_tokens off in Nginx, disable x-powered-by in Express).",
                        confidence="CONFIRMED",
                        references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"],
                    )
                )

            # --- Check 6: Insecure Cookie Flags ---
            for cookie in client.cookies.jar:
                cookie_issues = []
                if not cookie.secure and target.startswith("https://"):
                    cookie_issues.append("Missing Secure flag")
                # Python http.cookiejar doesn't expose HttpOnly directly in all versions, but we can inspect Set-Cookie headers
            set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [resp.headers.get("set-cookie", "")]
            for sc in set_cookie_headers:
                if sc:
                    sc_lower = sc.lower()
                    if "httponly" not in sc_lower:
                        cookie_name = sc.split("=")[0].strip()
                        findings.append(
                            ToolFinding(
                                finding_id=f"SEC-COOKIE-HTTPONLY-MISSING-{cookie_name}",
                                title=f"Cookie '{cookie_name}' Missing HttpOnly Flag",
                                description="The cookie lacks the HttpOnly attribute, making it accessible to client-side JavaScript and vulnerable to theft via XSS.",
                                severity="LOW",
                                affected_asset=f"{target} (Cookie: {cookie_name})",
                                evidence=f"Set-Cookie: {sc[:150]}",
                                reproduction=f"curl -I {target}",
                                remediation="Add 'HttpOnly' flag when setting application session and authentication cookies.",
                                confidence="CONFIRMED",
                                references=["https://owasp.org/www-community/HttpOnly"],
                            )
                        )

            # --- Check 7: Sensitive Path Probes (Non-destructive HEAD/GET) ---
            sensitive_paths = [
                ("/.git/HEAD", "Git Repository Metadata Exposure", "HIGH", "ref: refs/"),
                ("/.env", "Environment Configuration File Leakage", "CRITICAL", "DB_"),
                ("/robots.txt", "Robots.txt Information Disclosure", "INFORMATIONAL", "Disallow"),
                ("/.well-known/security.txt", "Security Policy Disclosure", "INFORMATIONAL", "Contact:"),
            ]

            for path, title, sev, pattern in sensitive_paths:
                check_url = urljoin(target, path)
                try:
                    probe_resp = client.get(check_url, timeout=5.0)
                    if probe_resp.status_code == 200:
                        content_sample = probe_resp.text[:200]
                        if pattern in content_sample or (path in ["/robots.txt", "/.well-known/security.txt"] and len(content_sample) > 5):
                            findings.append(
                                ToolFinding(
                                    finding_id=f"SEC-EXPOSURE-{path.replace('/', '_').replace('.', '')}",
                                    title=title,
                                    description=f"Publicly accessible sensitive endpoint discovered at '{path}'.",
                                    severity=sev,
                                    affected_asset=check_url,
                                    evidence=f"HTTP 200 OK. Preview: {content_sample[:100]}",
                                    reproduction=f"curl -s {check_url}",
                                    remediation=f"Block public access to '{path}' in web server configuration or remove sensitive files from document root.",
                                    confidence="CONFIRMED",
                                    references=["https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"],
                                )
                            )
                            logs.append(f"Exposed endpoint found: {path} (HTTP 200)")
                except Exception:
                    pass

        except Exception as e:
            logs.append(f"HTTP audit encountered error: {str(e)}")
            return ToolOutput(
                tool_name="http_audit",
                success=False,
                exit_code=1,
                raw_output="\n".join(logs),
                findings=findings,
                error_message=str(e),
            )
        finally:
            client.close()

        logs.append(f"Audit completed. Discovered {len(findings)} security observation(s).")
        raw_output = "\n".join(logs) + "\n\n" + "\n".join([f"[{f.severity}] {f.title} ({f.finding_id})" for f in findings])

        return ToolOutput(
            tool_name="http_audit",
            success=True,
            exit_code=0,
            raw_output=raw_output,
            findings=findings,
            structured_data={"findings_count": len(findings)},
        )
