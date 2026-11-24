"""Semgrep adapter for static application security testing (SAST)."""

import json
import shutil
import subprocess
from typing import Any, Dict
from sensei.tools.base import BaseToolAdapter
from sensei.tools.schemas import ToolCategory, ToolInfo, ToolOutput, ToolFinding


class SemgrepAdapter(BaseToolAdapter):
    """Adapter for Semgrep SAST code analysis."""

    def __init__(self):
        info = ToolInfo(
            name="semgrep",
            display_name="Semgrep Code Security",
            description="Static analysis engine for finding security bugs and anti-patterns in source code.",
            category=ToolCategory.CODE_SECURITY,
            version="1.60.0",
            input_schema={
                "target_path": {"type": "string", "default": ".", "description": "Directory or file to analyze"}
            },
            output_schema={"findings": "List of discovered code security vulnerabilities"},
            required_permissions="LOW",
            execution_method="cli_process",
            timeout_seconds=90,
            is_available=bool(shutil.which("semgrep")),
            install_guide="Install via: pip install semgrep or brew install semgrep",
        )
        super().__init__(info)

    def check_availability(self) -> bool:
        avail = bool(shutil.which("semgrep"))
        self.info.is_available = avail
        return avail

    def validate_input(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        path = input_data.get("target_path", ".")
        if not isinstance(path, str):
            path = "."
        return {"target_path": path}

    def _run_internal(self, input_data: Dict[str, Any], timeout: int) -> ToolOutput:
        path = input_data["target_path"]
        cmd = ["semgrep", "scan", "--config", "auto", "--json", "--quiet", path]

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)

        findings = []
        raw = proc.stdout or proc.stderr or ""
        try:
            data = json.loads(proc.stdout)
            for res in data.get("results", []):
                check_id = res.get("check_id", "semgrep-finding")
                extra = res.get("extra", {})
                findings.append(
                    ToolFinding(
                        finding_id=f"SAST-{check_id}",
                        title=extra.get("message", check_id),
                        description=extra.get("metadata", {}).get("description", extra.get("message", "")),
                        severity=extra.get("severity", "MEDIUM").upper(),
                        affected_asset=f"{res.get('path')}:{res.get('start', {}).get('line')}",
                        evidence=extra.get("lines", ""),
                        remediation=extra.get("metadata", {}).get("fix", "Review code pattern."),
                        confidence="CONFIRMED",
                    )
                )
        except Exception:
            pass

        return ToolOutput(
            tool_name="semgrep",
            success=(proc.returncode in (0, 1)),
            exit_code=proc.returncode,
            raw_output=raw,
            findings=findings,
            structured_data={"findings_count": len(findings)},
            error_message=proc.stderr if proc.returncode not in (0, 1) else None,
        )
