"""Nmap adapter for safe network port and service discovery."""

import shutil
import subprocess
from typing import Any, Dict
from urllib.parse import urlparse
from sensei.tools.base import BaseToolAdapter
from sensei.tools.schemas import ToolCategory, ToolInfo, ToolOutput, ToolFinding


class NmapAdapter(BaseToolAdapter):
    """Adapter for Nmap network mapper running safe, non-destructive port scans."""

    def __init__(self):
        info = ToolInfo(
            name="nmap",
            display_name="Nmap Network Scanner",
            description="Network exploration and service discovery scanner performing safe port checks.",
            category=ToolCategory.NETWORK_SECURITY,
            version="7.94",
            input_schema={
                "target": {"type": "string", "description": "Target hostname or IP"},
                "ports": {"type": "string", "default": "80,443,3000,8000,8080", "description": "Comma-separated ports"},
            },
            output_schema={"raw_output": "Open ports and service version details"},
            required_permissions="LOW",
            execution_method="cli_process",
            timeout_seconds=60,
            is_available=bool(shutil.which("nmap")),
            install_guide="Download and install Nmap from https://nmap.org/download.html or via package manager.",
        )
        super().__init__(info)

    def check_availability(self) -> bool:
        avail = bool(shutil.which("nmap"))
        self.info.is_available = avail
        return avail

    def validate_input(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        target = input_data.get("target")
        if not target or not isinstance(target, str):
            raise ValueError("Target hostname or IP is required.")
        target = target.strip()
        if "://" in target:
            target = urlparse(target).hostname or target
        target = target.split("/")[0]

        ports = input_data.get("ports", "80,443,3000,8000,8080")
        clean_ports = ",".join(
            p.strip() for p in str(ports).split(",") if p.strip().isdigit() and 1 <= int(p.strip()) <= 65535
        )
        if not clean_ports:
            clean_ports = "80,443,3000,8000,8080"

        return {"target": target, "ports": clean_ports}

    def _run_internal(self, input_data: Dict[str, Any], timeout: int) -> ToolOutput:
        target = input_data["target"]
        ports = input_data["ports"]

        # Safe non-intrusive command flags (no aggressive scripts or DoS)
        cmd = [
            "nmap",
            "-sV",
            "--version-light",
            "-Pn",
            "-p", ports,
            target,
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)

        findings = []
        raw = proc.stdout or proc.stderr or ""
        for line in raw.splitlines():
            if "/tcp" in line and "open" in line:
                parts = line.split()
                port = parts[0]
                service = parts[2] if len(parts) > 2 else "unknown"
                findings.append(
                    ToolFinding(
                        finding_id=f"NET-PORT-OPEN-{port.replace('/', '_')}",
                        title=f"Open Port Discovered: {port} ({service})",
                        description=f"Service {service} is exposed on open port {port}.",
                        severity="INFORMATIONAL",
                        affected_asset=f"{target}:{port}",
                        evidence=line,
                        reproduction=f"nmap -p {port} {target}",
                        remediation="Verify whether this port is required to be exposed. Close or firewall unneeded services.",
                        confidence="CONFIRMED",
                    )
                )

        return ToolOutput(
            tool_name="nmap",
            success=(proc.returncode == 0),
            exit_code=proc.returncode,
            raw_output=raw,
            findings=findings,
            structured_data={"open_ports_count": len(findings)},
            error_message=proc.stderr if proc.returncode != 0 else None,
        )
