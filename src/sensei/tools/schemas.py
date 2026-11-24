"""Schemas for tool registry, metadata, inputs, and outputs."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ToolCategory(str, Enum):
    """Categorization of security tools in Sensei."""
    NETWORK_SECURITY = "Network Security"
    WEB_SECURITY = "Web Application Security"
    CODE_SECURITY = "Code Security"
    INFRASTRUCTURE_SECURITY = "Infrastructure Security"
    BROWSER_AUTOMATION = "Browser Automation"
    AI_SECURITY = "AI Security"


class ToolInfo(BaseModel):
    """Metadata describing a registered security tool."""
    name: str = Field(..., description="Unique tool identifier")
    display_name: str = Field(..., description="Human-friendly name")
    description: str = Field(..., description="Detailed description of tool capabilities")
    category: ToolCategory = Field(..., description="Tool category")
    version: str = Field(default="1.0.0")
    input_schema: Dict[str, Any] = Field(default_factory=dict, description="Expected input parameters")
    output_schema: Dict[str, Any] = Field(default_factory=dict, description="Expected output format")
    required_permissions: str = Field(default="LOW", description="Required risk tier: SAFE, LOW, MEDIUM, HIGH")
    execution_method: str = Field(default="native_adapter", description="native_adapter, cli_process, docker, or mcp")
    timeout_seconds: int = Field(default=60, description="Default timeout in seconds")
    is_available: bool = Field(default=False, description="Whether tool binary/environment is detected")
    install_guide: str = Field(default="", description="Command or instructions to install if missing")


class ToolFinding(BaseModel):
    """Individual security finding extracted from a tool execution."""
    finding_id: str
    title: str
    description: str
    severity: str = "INFORMATIONAL"  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    affected_asset: str
    evidence: str = ""
    reproduction: str = ""
    remediation: str = ""
    confidence: str = "CONFIRMED"     # CONFIRMED, HIGH, MEDIUM, LOW
    references: List[str] = Field(default_factory=list)


class ToolOutput(BaseModel):
    """Standardized output model returned by all tool adapters."""
    tool_name: str
    success: bool
    exit_code: int = 0
    raw_output: str = ""
    structured_data: Dict[str, Any] = Field(default_factory=dict)
    findings: List[ToolFinding] = Field(default_factory=list)
    duration_seconds: float = 0.0
    is_truncated: bool = False
    error_message: Optional[str] = None
