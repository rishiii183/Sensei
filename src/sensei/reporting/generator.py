"""Multi-format security report generator (Markdown, JSON, HTML)."""

import html
import uuid
from pathlib import Path
from typing import List, Optional
from sensei.config import get_config
from sensei.memory.repository import SenseiRepository
from sensei.reporting.models import Finding, SecurityReport


class ReportGenerator:
    """Builds and exports evidence-based security reports."""

    def __init__(self, repo: Optional[SenseiRepository] = None):
        self.repo = repo or SenseiRepository()

    def build_report(
        self,
        session_id: str,
        target: str,
        operating_mode: str,
        findings: List[Finding],
        tools_executed: List[str],
        methodology: Optional[List[str]] = None,
        mentor_notes: str = "",
        title: Optional[str] = None,
    ) -> SecurityReport:
        """Construct a SecurityReport with computed severity statistics."""
        report = SecurityReport(
            report_id=str(uuid.uuid4())[:8],
            session_id=session_id,
            title=title or f"Sensei Security Assessment Report - {target}",
            target=target,
            operating_mode=operating_mode,
            executive_summary=self._build_executive_summary(target, findings, tools_executed),
            methodology=methodology or ["Non-destructive reconnaissance and security posture audit"],
            findings=findings,
            tools_executed=tools_executed,
            mentor_notes=mentor_notes,
        )
        report.compute_counts()
        return report

    def _build_executive_summary(
        self, target: str, findings: List[Finding], tools_executed: List[str]
    ) -> str:
        confirmed = sum(1 for f in findings if f.validation_status.value == "CONFIRMED")
        potential = sum(1 for f in findings if f.validation_status.value == "POTENTIAL")
        info = sum(1 for f in findings if f.validation_status.value == "INFORMATIONAL")
        tools_str = ", ".join(tools_executed) if tools_executed else "none"
        return (
            f"Authorized non-destructive security assessment of '{target}' executed using [{tools_str}]. "
            f"Identified {len(findings)} total observation(s): {confirmed} CONFIRMED, "
            f"{potential} POTENTIAL, and {info} INFORMATIONAL."
        )

    def to_markdown(self, report: SecurityReport) -> str:
        """Render report in Markdown format."""
        lines = [
            f"# {report.title}",
            "",
            f"- **Report ID:** `{report.report_id}`",
            f"- **Session ID:** `{report.session_id}`",
            f"- **Target:** `{report.target}`",
            f"- **Operating Mode:** `{report.operating_mode}`",
            f"- **Generated At:** `{report.generated_at}`",
            f"- **Tools Executed:** {', '.join(report.tools_executed) or 'None'}",
            "",
            "## Executive Summary",
            report.executive_summary,
            "",
            "## Severity Breakdown",
            "| Severity | Count |",
            "| --- | ---: |",
        ]
        for sev, count in report.severity_counts.items():
            lines.append(f"| {sev} | {count} |")

        lines.extend(["", "## Methodology"])
        for step in report.methodology:
            lines.append(f"- {step}")

        lines.extend(["", "## Findings"])
        if not report.findings:
            lines.append("No vulnerabilities or exposures were identified.")
        else:
            for idx, f in enumerate(report.findings, start=1):
                lines.extend([
                    f"### {idx}. [{f.severity.value}] {f.title}",
                    f"- **Finding ID:** `{f.finding_id}`",
                    f"- **Validation Status:** `{f.validation_status.value}` (Confidence: `{f.confidence_level.value}`)",
                    f"- **Affected Asset:** `{f.affected_asset}`",
                    "",
                    f"**Description:** {f.description}",
                    "",
                    f"**Evidence:**\n```\n{f.evidence}\n```",
                    "",
                    f"**Reproduction Methodology:** `{f.reproduction_methodology}`",
                    "",
                    f"**Potential Impact:** {f.potential_impact}",
                    "",
                    f"**Remediation:** {f.remediation}",
                    "",
                ])
                if f.references:
                    lines.append("**References:**")
                    for ref in f.references:
                        lines.append(f"- {ref}")
                    lines.append("")

        if report.mentor_notes:
            lines.extend(["## Security Mentor Takeaways", report.mentor_notes, ""])

        return "\n".join(lines)

    def to_json(self, report: SecurityReport) -> str:
        """Render report in JSON format."""
        return report.model_dump_json(indent=2)

    def to_html(self, report: SecurityReport) -> str:
        """Render report as a clean, XSS-safe standalone HTML document."""
        esc = html.escape
        rows = []
        for f in report.findings:
            rows.append(
                f"<div class='finding'>"
                f"<h3>[{esc(f.severity.value)}] {esc(f.title)}</h3>"
                f"<p><strong>ID:</strong> <code>{esc(f.finding_id)}</code> | "
                f"<strong>Status:</strong> {esc(f.validation_status.value)} | "
                f"<strong>Asset:</strong> <code>{esc(f.affected_asset)}</code></p>"
                f"<p>{esc(f.description)}</p>"
                f"<pre>{esc(f.evidence)}</pre>"
                f"<p><strong>Remediation:</strong> {esc(f.remediation)}</p>"
                f"</div>"
            )
        findings_html = "\n".join(rows) if rows else "<p>No findings discovered.</p>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>{esc(report.title)}</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #1f2937; }}
  h1, h2 {{ border-bottom: 1px solid #e5e7eb; padding-bottom: 0.4rem; }}
  .meta {{ background: #f9fafb; padding: 1rem; border-radius: 6px; margin-bottom: 1.5rem; }}
  .finding {{ border: 1px solid #e5e7eb; border-radius: 6px; padding: 1rem; margin-bottom: 1rem; }}
  pre {{ background: #111827; color: #f3f4f6; padding: 0.75rem; border-radius: 4px; overflow-x: auto; }}
</style>
</head>
<body>
  <h1>{esc(report.title)}</h1>
  <div class="meta">
    <p><strong>Target:</strong> {esc(report.target)} | <strong>Mode:</strong> {esc(report.operating_mode)} | <strong>Generated:</strong> {esc(report.generated_at)}</p>
    <p>{esc(report.executive_summary)}</p>
  </div>
  <h2>Findings</h2>
  {findings_html}
  <h2>Security Mentor Takeaways</h2>
  <pre>{esc(report.mentor_notes)}</pre>
</body>
</html>"""

    def save_report(
        self,
        report: SecurityReport,
        fmt: str = "markdown",
        reports_dir: Optional[Path] = None,
    ) -> Path:
        """Export report to disk and record in SQLite."""
        target_dir = reports_dir or get_config().reports_dir
        target_dir.mkdir(parents=True, exist_ok=True)

        fmt_lower = fmt.lower()
        if fmt_lower in ("md", "markdown"):
            ext = "md"
            content = self.to_markdown(report)
            fmt_name = "markdown"
        elif fmt_lower == "json":
            ext = "json"
            content = self.to_json(report)
            fmt_name = "json"
        elif fmt_lower == "html":
            ext = "html"
            content = self.to_html(report)
            fmt_name = "html"
        else:
            raise ValueError(f"Unsupported report format '{fmt}'. Use markdown, json, or html.")

        filename = f"sensei_report_{report.session_id[:8]}_{report.report_id}.{ext}"
        file_path = target_dir / filename
        file_path.write_text(content, encoding="utf-8")

        try:
            self.repo.save_report(
                session_id=report.session_id,
                format_name=fmt_name,
                title=report.title,
                content=content,
                file_path=str(file_path),
            )
        except Exception:
            pass

        return file_path
