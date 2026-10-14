"""
©AngelaMos | 2026
scoring.py
"""


import structlog

from dlp_scanner.compliance import (
    get_frameworks_for_rule,
    get_remediation_for_rule,
    score_to_severity,
)
from dlp_scanner.constants import RedactionStyle
from dlp_scanner.detectors.base import DetectorMatch
from dlp_scanner.models import Finding, Location
from dlp_scanner.redaction import redact
from dlp_scanner.config import ComplianceConfig

log = structlog.get_logger()


def match_to_finding(
    match: DetectorMatch,
    text: str,
    location: Location,
    redaction_style: RedactionStyle,
    compliance_config: "ComplianceConfig | None" = None,
) -> Finding:
    """
    Convert a detector match into a fully classified finding.

    If *compliance_config* is supplied and its ``severity_overrides``
    mapping is non-empty, the confidence-derived severity may be elevated
    to satisfy a per-framework severity floor.  The confidence score is
    never changed — only the severity label.
 
    :param match: Raw detector output (rule id, span, score, …).
    :param text: Full text that was scanned (used to build the redacted
        snippet).
    :param location: Source location of the text chunk.
    :param redaction_style: How to redact the matched value in the
        snippet.
    :param compliance_config: Optional :class:`ComplianceConfig` instance.
        When ``None`` (the default), no override logic runs and the
        behaviour is identical to the original implementation.
    :returns: A :class:`~dlp_scanner.models.Finding` ready to be stored
        in a :class:`~dlp_scanner.models.ScanResult`.
    """

    confidence_severity = score_to_severity(match.score)
    frameworks = get_frameworks_for_rule(match.rule_id)
    if match.compliance_frameworks:
        combined = (
            set(frameworks) | set(match.compliance_frameworks)
        )
        frameworks = sorted(combined)
    remediation = get_remediation_for_rule(match.rule_id)

    # Apply compliance severity floor
    effective_severity = confidence_severity
    if compliance_config is not None:
        effective_severity, override_reason = (
            compliance_config.effective_severity(
                confidence_severity,
                frameworks,
            )
        )
        if override_reason is not None:
            log.debug(
                "severity_overridden_by_compliance",
                rule_id = match.rule_id,
                confidence_score = round(match.score, 4),
                original_severity = confidence_severity,
                effective_severity = effective_severity,
                triggered_by = override_reason,
                location_uri = location.uri,
            )

    snippet = redact(
        text,
        match.start,
        match.end,
        style = redaction_style,
    )

    return Finding(
        rule_id = match.rule_id,
        rule_name = match.rule_name,
        severity = effective_severity,
        confidence = match.score,
        location = location,
        redacted_snippet = snippet,
        compliance_frameworks = frameworks,
        remediation = remediation,
    )
