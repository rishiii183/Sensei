"""Nuclei tool adapter running verified safe, non-destructive vulnerability templates."""

import json
import shutil
import subprocess
from typing import Any, Dict
from urllib.parse import urlparse
from sensei.tools.base import BaseToolAdapter
from sensei.tools.schemas import ToolCategory, ToolInfo, ToolOutput, ToolFinding


class NucleiAdapter(BaseToolAdapter):
    """Adapter for ProjectDiscovery Nuclei vulnerability scanner."""

    def __init__(self):
        info = ToolInfo(
            name="nuclei",
            display_name="ProjectDiscovery Nuclei",
            description="Fast and customizable vulnerability scanner using safe, non-destructive YAML templates.",
            category=ToolCategory.WEB_SECURITY,
            version="3.3.0",
            input_schema={
                "target": {"type": "string", "description": "Target URL (e.g. http://localhost:3000)"},
                "severity": {"type": "string", "default": "info,low", "description": "Severity filter"},
                "tags": {"type": "string", "default": "cve,misconfig,tech", "description": "Safe template tags"},
            },
            output_schema={"findings": "List of discovered vulnerabilities and technology observations"},
            required_permissions="LOW",
            execution_method="cli_process",
            timeout_seconds=90,
            is_available=bool(shutil.which("nuclei")),
            install_guide="Install via: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest or download from github.com/projectdiscovery/nuclei/releases",
        )
        super().__init__(info)

    def check_availability(self) -> bool:
        """Check if nuclei binary is available in system PATH."""
        avail = bool(shutil.which("nuclei"))
        self.info.is_available = avail
        return avail

    def validate_input(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate input to prevent arbitrary flag or shell injection."""
        target = input_data.get("target")
        if not target or not isinstance(target, str):
            raise ValueError("Target must be a non-empty string.")

        target = target.strip()
        if not (target.startswith("http://") or target.startswith("https://")):
            # Default to http:// if no scheme provided
            target = f"http://{target}"

        # Ensure hostname is valid
        parsed = urlparse(target)
        if not parsed.netloc:
            raise ValueError(f"Invalid target URL structure: '{target}'")

        # Whitelist safe severities and tags
        severity = input_data.get("severity", "info,low")
        # Ensure only safe non-destructive severities are allowed by default
        safe_severities = {"info", "low", "medium"}
        requested_sevs = [s.strip().lower() for s in str(severity).split(",") if s.strip()]
        validated_sevs = [s for s in requested_sevs if s in safe_severities]
        if not validated_sevs:
            validated_sevs = ["info", "low"]

        tags = input_data.get("tags", "cve,misconfig,tech")
        # Clean tags (alphanumeric, comma, dash, underscore only)
        clean_tags = ",".join(
            t.strip() for t in str(tags).split(",") if t.strip().replace("-", "").replace("_", "").isalnum()
        )
        if not clean_tags:
            clean_tags = "cve,misconfig,tech"

        return {
            "target": target,
            "severity": ",".join(validated_sevs),
            "tags": clean_tags,
        }

    def _run_internal(self, input_data: Dict[str, Any], timeout: int) -> ToolOutput:
        """Execute nuclei binary with strictly structured argument list."""
        target = input_data["target"]
        severity = input_data["severity"]
        tags = input_data["tags"]

        # Strict arguments list (Never shell=True)
        cmd = [
            "nuclei",
            "-target", target,
            "-tags", tags,
            "-severity", severity,
            "-jsonl",
            "-silent",
            "-rate-limit", "5",
            "-timeout", "10",
            "-retries", "1",
            "-disable-update-check",
        ]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )

        findings = []
        raw_lines = []

        if proc.stdout:
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                raw_lines.append(line)
                try:
                    data = json.loads(line)
                    info = data.get("info", {})
                    finding = ToolFinding(
                        finding_id=data.get("template-id", "nuclei-finding"),
                        title=info.get("name", data.get("template-id", "Security Issue")),
                        description=info.get("description", "Vulnerability detected by Nuclei template."),
                        severity=info.get("severity", "INFORMATIONAL").upper(),
                        affected_asset=data.get("matched-at", target),
                        evidence=data.get("curl-command") or line[:300],
                        remediation=info.get("remediation", ""),
                        confidence="CONFIRMED",
                        references=info.get("reference", []) if isinstance(info.get("reference"), list) else [],
                    )
                    findings.append(finding)
                except Exception:
                    pass

        raw_output = "\n".join(raw_lines) if raw_lines else (proc.stdout or proc.stderr or "No vulnerabilities detected by safe templates.")

        return ToolOutput(
            tool_name="nuclei",
            success=(proc.returncode == 0),
            exit_code=proc.returncode,
            raw_output=raw_output,
            findings=findings,
            structured_data={"findings_count": len(findings)},
            error_message=proc.stderr if proc.returncode != 0 else None,
        )
