"""Security Mentor Specialist for teaching security concepts behind findings."""

from typing import List, Optional
from sensei.agent.llm import CostTracker, SenseiLLMClient
from sensei.reporting.models import Finding
from sensei.security.sanitizer import wrap_untrusted_data


class SecurityMentor:
    """Explains discovered vulnerabilities, attack mechanics, and defensive fixes."""

    def __init__(self, llm_client: Optional[SenseiLLMClient] = None):
        self.llm = llm_client or SenseiLLMClient()

    def explain(
        self,
        objective: str,
        target: str,
        findings: List[Finding],
        tracker: Optional[CostTracker] = None,
    ) -> str:
        """Produce clear, actionable security mentorship based on validated findings."""
        if not findings:
            return (
                f"No vulnerabilities were confirmed on {target} by the executed non-destructive checks. "
                "Security Tip: Continue maintaining defense-in-depth with strict HTTP security headers, "
                "least-privilege access controls, and periodic dependency audits."
            )

        status = self.llm.get_status()
        if status.active_provider != "local_heuristic":
            summary_lines = [
                f"- [{f.severity.value}] {f.title} ({f.validation_status.value}): {f.description}"
                for f in findings[:8]
            ]
            safe_context = wrap_untrusted_data("\n".join(summary_lines), source_label="Validated Findings")
            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are Sensei's Security Mentor. Explain the security concepts behind the confirmed "
                        "findings concisely (3-5 bullet points), why attackers care about them, and how to fix them "
                        "using defense-in-depth. Never generate exploit payloads."
                    ),
                },
                {
                    "role": "user",
                    "content": f"Objective: {objective}\nTarget: {target}\n{safe_context}",
                },
            ]
            content, _ = self.llm.complete(messages, tracker=tracker, max_tokens=500)
            if content:
                return content.strip()

        return self._explain_deterministic(target, findings)

    def _explain_deterministic(self, target: str, findings: List[Finding]) -> str:
        """Deterministic educational breakdown when running without external LLM."""
        lessons: List[str] = [
            f"Security Mentor Summary for {target} ({len(findings)} observation(s)):"
        ]

        seen_topics = set()
        for f in findings:
            fid = f.finding_id.upper()
            if "CSP" in fid and "csp" not in seen_topics:
                seen_topics.add("csp")
                lessons.append(
                    "• Content-Security-Policy (CSP): CSP acts as an allowlist telling browsers which script "
                    "and resource origins are trusted. Without it, a single XSS flaw lets injected scripts execute freely."
                )
            elif "XFO" in fid and "xfo" not in seen_topics:
                seen_topics.add("xfo")
                lessons.append(
                    "• Anti-Clickjacking (X-Frame-Options / frame-ancestors): Without framing restrictions, "
                    "an attacker can overlay your app inside a hidden iframe and trick authenticated users into clicking sensitive buttons."
                )
            elif "XCTO" in fid and "xcto" not in seen_topics:
                seen_topics.add("xcto")
                lessons.append(
                    "• MIME Sniffing (X-Content-Type-Options: nosniff): Prevents browsers from guessing content types "
                    "and mistakenly executing uploaded text or image files as JavaScript."
                )
            elif "COOKIE" in fid and "cookie" not in seen_topics:
                seen_topics.add("cookie")
                lessons.append(
                    "• Cookie Security Flags (HttpOnly / Secure / SameSite): Setting HttpOnly prevents client-side "
                    "JavaScript (`document.cookie`) from reading session tokens, limiting XSS session hijacking."
                )
            elif "BANNER" in fid and "banner" not in seen_topics:
                seen_topics.add("banner")
                lessons.append(
                    "• Server Banner Minimization: Advertising exact web server or framework versions helps automated "
                    "scanners quickly match known CVEs. Strip `Server` and `X-Powered-By` headers in production."
                )
            elif "EXPOSURE" in fid and "exposure" not in seen_topics:
                seen_topics.add("exposure")
                lessons.append(
                    "• Sensitive Path Exposure: Files like `.env`, `.git/HEAD`, or unauthenticated admin routes "
                    "leak configuration secrets or source history. Always deny access at the reverse proxy/web server."
                )

        if len(lessons) == 1:
            lessons.append(
                "• Defense-in-Depth: Review each validated finding's remediation steps and verify fixes by re-running the audit."
            )

        return "\n".join(lessons)
