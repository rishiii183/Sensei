"""Gitleaks adapter for detecting hardcoded secrets and tokens."""

import json
import shutil
import subprocess
from typing import Any, Dict
from sensei.tools.base import BaseToolAdapter
from sensei.tools.schemas import ToolCategory, ToolInfo, ToolOutput, ToolFinding


class GitleaksAdapter(BaseToolAdapter):
    """Adapter for Gitleaks secrets detection engine."""

    def __init__(self):
        info = ToolInfo(
            name="gitleaks",
            display_name="Gitleaks Secret Scanner",
            description="Audits git repositories and files for hardcoded secrets, API keys, and credentials.",
            category=ToolCategory.CODE_SECURITY,
            version="8.18.0",
            input_schema={"source": {"type": "string", "default": ".", "description": "Path to scan"}},
            output_schema={"findings": "List of exposed credentials and tokens"},
            required_permissions="LOW",
            execution_method="cli_process",
            timeout_seconds=60,
            is_available=bool(shutil.which("gitleaks")),
            install_guide="Download Gitleaks from https://github.com/gitleaks/gitleaks/releases or brew install gitleaks",
        )
        super().__init__(info)

    def check_availability(self) -> bool:
        avail = bool(shutil.which("gitleaks"))
        self.info.is_available = avail
        return avail

    def validate_input(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        source = input_data.get("source", ".")
        return {"source": str(source).strip() or "."}

    def _run_internal(self, input_data: Dict[str, Any], timeout: int) -> ToolOutput:
        source = input_data["source"]
        cmd = ["gitleaks", "dir", "--report-format", "json", "--source", source, "--redact", "--verbose"]

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)

        findings = []
        raw = proc.stdout or proc.stderr or ""
        try:
            items = json.loads(proc.stdout) if proc.stdout else []
            for item in items:
                rule_id = item.get("RuleID", "secret-detected")
                findings.append(
                    ToolFinding(
                        finding_id=f"SECRET-{rule_id}",
                        title=f"Hardcoded Secret Disclosed: {item.get('Description', rule_id)}",
                        description=f"Secret identified in {item.get('File')}:{item.get('StartLine')}",
                        severity="HIGH",
                        affected_asset=f"{item.get('File')}:{item.get('StartLine')}",
                        evidence=f"Match: {item.get('Match', 'REDACTED')}",
                        remediation="Rotate exposed credential immediately and revoke compromised keys. Remove from git history.",
                        confidence="CONFIRMED",
                    )
                )
        except Exception:
            pass

        return ToolOutput(
            tool_name="gitleaks",
            success=(proc.returncode in (0, 1)),
            exit_code=proc.returncode,
            raw_output=raw,
            findings=findings,
            structured_data={"findings_count": len(findings)},
            error_message=proc.stderr if proc.returncode not in (0, 1) else None,
        )
