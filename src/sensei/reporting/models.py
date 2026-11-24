"""Structured reporting and finding models for evidence-based security reports."""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class ValidationStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    POTENTIAL = "POTENTIAL"
    INFORMATIONAL = "INFORMATIONAL"


class ConfidenceLevel(str, Enum):
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Finding(BaseModel):
    """Comprehensive evidence-based security finding model."""

    finding_id: str
    title: str
    description: str
    severity: SeverityLevel = SeverityLevel.INFORMATIONAL
    affected_asset: str
    evidence: str
    reproduction_methodology: str = ""
    confidence_level: ConfidenceLevel = ConfidenceLevel.CONFIRMED
    potential_impact: str = ""
    remediation: str = ""
    references: List[str] = Field(default_factory=list)
    validation_status: ValidationStatus = ValidationStatus.CONFIRMED


class SecurityReport(BaseModel):
    """Structured security assessment report."""

    report_id: str
    session_id: str
    title: str
    target: str
    operating_mode: str
    executive_summary: str
    methodology: List[str] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    severity_counts: Dict[str, int] = Field(default_factory=dict)
    tools_executed: List[str] = Field(default_factory=list)
    mentor_notes: str = ""
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def compute_counts(self) -> Dict[str, int]:
        """Compute counts by severity."""
        counts = {s.value: 0 for s in SeverityLevel}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        self.severity_counts = counts
        return counts
