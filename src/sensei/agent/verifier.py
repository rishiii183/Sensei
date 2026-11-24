"""Result Validator ensuring evidence-based reporting and false-positive filtering."""

from typing import Dict, List
from sensei.tools.schemas import ToolFinding
from sensei.reporting.models import (
    ConfidenceLevel,
    Finding,
    SeverityLevel,
    ValidationStatus,
)


class ResultValidator:
    """Validates raw tool findings, deduplicates them, and assigns confidence/validation status."""

    def validate(self, raw_findings: List[ToolFinding]) -> List[Finding]:
        """Convert raw tool findings into deduplicated, evidence-backed Finding records."""
        deduped: Dict[str, Finding] = {}

        for raw in raw_findings:
            key = f"{raw.finding_id}::{raw.affected_asset}".lower()
            if key in deduped:
                continue

            severity = self._parse_severity(raw.severity)
            has_evidence = bool(raw.evidence and raw.evidence.strip())

            # Evidence-based classification: never claim CONFIRMED without technical evidence
            if severity == SeverityLevel.INFORMATIONAL:
                val_status = ValidationStatus.INFORMATIONAL
                conf = ConfidenceLevel.CONFIRMED if has_evidence else ConfidenceLevel.LOW
            elif has_evidence:
                val_status = ValidationStatus.CONFIRMED
                conf = self._parse_confidence(raw.confidence)
            else:
                val_status = ValidationStatus.POTENTIAL
                conf = ConfidenceLevel.LOW

            impact = self._infer_impact(severity, raw.title)
            repro = raw.reproduction or f"Inspect response headers/body for {raw.affected_asset}"
            remediation = raw.remediation or "Review security configuration and apply defense-in-depth hardening."

            deduped[key] = Finding(
                finding_id=raw.finding_id,
                title=raw.title,
                description=raw.description,
                severity=severity,
                affected_asset=raw.affected_asset,
                evidence=raw.evidence if has_evidence else "No direct technical proof captured; marked as POTENTIAL.",
                reproduction_methodology=repro,
                confidence_level=conf,
                potential_impact=impact,
                remediation=remediation,
                references=raw.references,
                validation_status=val_status,
            )

        severity_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFORMATIONAL: 4,
        }
        return sorted(deduped.values(), key=lambda f: severity_order.get(f.severity, 99))

    def _parse_severity(self, sev_str: str) -> SeverityLevel:
        normalized = sev_str.strip().upper()
        if normalized in ("INFO", "INFORMATIONAL"):
            return SeverityLevel.INFORMATIONAL
        try:
            return SeverityLevel(normalized)
        except ValueError:
            return SeverityLevel.LOW

    def _parse_confidence(self, conf_str: str) -> ConfidenceLevel:
        try:
            return ConfidenceLevel(conf_str.strip().upper())
        except ValueError:
            return ConfidenceLevel.MEDIUM

    def _infer_impact(self, severity: SeverityLevel, title: str) -> str:
        if severity == SeverityLevel.CRITICAL:
            return f"Immediate critical risk: '{title}' could allow direct exposure of sensitive data or unauthorized control."
        if severity == SeverityLevel.HIGH:
            return f"High security impact: '{title}' significantly weakens application boundary protections."
        if severity == SeverityLevel.MEDIUM:
            return f"Moderate impact: '{title}' increases attack surface or weakens browser/transport defenses."
        if severity == SeverityLevel.LOW:
            return f"Low impact defense-in-depth gap related to '{title}'."
        return f"Informational observation regarding '{title}' useful for attack surface hygiene."
