"""Trivy adapter for infrastructure and container security testing."""

import json
import shutil
import subprocess
from typing import Any, Dict
from sensei.tools.base import BaseToolAdapter
from sensei.tools.schemas import ToolCategory, ToolInfo, ToolOutput, ToolFinding


class TrivyAdapter(BaseToolAdapter):
    """Adapter for Aqua Security Trivy vulnerability scanner."""

    def __init__(self):
        info = ToolInfo(
            name="trivy",
            display_name="Trivy Vulnerability Scanner",
            description="Comprehensive security scanner for container images, filesystems, and Git repositories.",
            category=ToolCategory.INFRASTRUCTURE_SECURITY,
            version="0.50.0",
            input_schema={"target": {"type": "string", "default": ".", "description": "Filesystem path or image name"}},
            output_schema={"findings": "List of discovered CVEs and misconfigurations"},
            required_permissions="LOW",
            execution_method="cli_process",
            timeout_seconds=90,
            is_available=bool(shutil.which("trivy")),
            install_guide="Download Trivy from https://github.com/aquasecurity/trivy/releases or via brew/apt.",
        )
        super().__init__(info)

    def check_availability(self) -> bool:
        avail = bool(shutil.which("trivy"))
        self.info.is_available = avail
        return avail

    def validate_input(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        target = input_data.get("target", ".")
        return {"target": str(target).strip() or "."}

    def _run_internal(self, input_data: Dict[str, Any], timeout: int) -> ToolOutput:
        target = input_data["target"]
        cmd = ["trivy", "fs", "--format", "json", "--quiet", target]

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)

        findings = []
        raw = proc.stdout or proc.stderr or ""
        try:
            data = json.loads(proc.stdout)
            for res in data.get("Results", []):
                target_name = res.get("Target", target)
                for vuln in res.get("Vulnerabilities", []):
                    cve = vuln.get("VulnerabilityID", "CVE-UNKNOWN")
                    findings.append(
                        ToolFinding(
                            finding_id=f"INFRA-{cve}",
                            title=f"{cve}: {vuln.get('PkgName', '')} ({vuln.get('InstalledVersion', '')})",
                            description=vuln.get("Description", vuln.get("Title", "")),
                            severity=vuln.get("Severity", "MEDIUM").upper(),
                            affected_asset=f"{target_name} -> {vuln.get('PkgName')}",
                            evidence=f"Installed: {vuln.get('InstalledVersion')}, Fixed: {vuln.get('FixedVersion', 'None')}",
                            remediation=f"Upgrade {vuln.get('PkgName')} to version {vuln.get('FixedVersion', 'latest')}",
                            confidence="CONFIRMED",
                            references=vuln.get("References", []),
                        )
                    )
        except Exception:
            pass

        return ToolOutput(
            tool_name="trivy",
            success=(proc.returncode == 0),
            exit_code=proc.returncode,
            raw_output=raw,
            findings=findings,
            structured_data={"findings_count": len(findings)},
            error_message=proc.stderr if proc.returncode != 0 else None,
        )
