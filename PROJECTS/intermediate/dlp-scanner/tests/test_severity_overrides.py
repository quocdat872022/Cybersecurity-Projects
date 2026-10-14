"""
tests/test_severity_overrides.py
---------------------------------
Unit tests for Challenge 5 — compliance-driven severity floors.

These tests are deliberately dependency-light: they exercise the pure
Python logic in ``ComplianceConfig.effective_severity`` and the thin
wrapper in ``match_to_finding`` without requiring the full scan pipeline
or any file I/O.
"""

import pytest
from unittest.mock import MagicMock
from dlp_scanner.config import ComplianceConfig, ScanConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_compliance_config(overrides: dict) -> "ComplianceConfig":
    """Import-deferred factory so tests remain runnable as plain pytest."""
    return ComplianceConfig(severity_overrides=overrides)


def make_match(score: float, rule_id: str = "FIN_CREDIT_CARD_VISA"):
    from dlp_scanner.detectors.base import DetectorMatch
    return DetectorMatch(
        rule_id=rule_id,
        rule_name="Test Rule",
        start=0,
        end=4,
        matched_text="test",
        score=score,
        context_keywords=[],
        compliance_frameworks=[],
    )


# ---------------------------------------------------------------------------
# ComplianceConfig.effective_severity — pure unit tests
# ---------------------------------------------------------------------------

class TestEffectiveSeverity:

    def test_no_overrides_returns_original(self):
        cfg = make_compliance_config({})
        sev, reason = cfg.effective_severity("low", ["PCI_DSS"])
        assert sev == "low"
        assert reason is None

    def test_override_elevates_low_to_high(self):
        cfg = make_compliance_config({"PCI_DSS": "high"})
        sev, reason = cfg.effective_severity("low", ["PCI_DSS"])
        assert sev == "high"
        assert reason == "PCI_DSS"

    def test_override_does_not_demote(self):
        """A 'critical' finding with PCI_DSS:high must stay 'critical'."""
        cfg = make_compliance_config({"PCI_DSS": "high"})
        sev, reason = cfg.effective_severity("critical", ["PCI_DSS"])
        assert sev == "critical"
        assert reason is None

    def test_finding_not_in_framework_unaffected(self):
        """Override for PCI_DSS must not affect a GDPR-only finding."""
        cfg = make_compliance_config({"PCI_DSS": "high"})
        sev, reason = cfg.effective_severity("low", ["GDPR"])
        assert sev == "low"
        assert reason is None

    def test_highest_floor_wins_across_multiple_frameworks(self):
        """If HIPAA:medium and PCI_DSS:high both apply, use 'high'."""
        cfg = make_compliance_config({"HIPAA": "medium", "PCI_DSS": "high"})
        sev, reason = cfg.effective_severity("low", ["HIPAA", "PCI_DSS"])
        assert sev == "high"
        assert reason == "PCI_DSS"

    def test_medium_floor_elevates_low(self):
        cfg = make_compliance_config({"HIPAA": "medium"})
        sev, reason = cfg.effective_severity("low", ["HIPAA"])
        assert sev == "medium"
        assert reason == "HIPAA"

    def test_medium_floor_does_not_elevate_high(self):
        cfg = make_compliance_config({"HIPAA": "medium"})
        sev, reason = cfg.effective_severity("high", ["HIPAA"])
        assert sev == "high"
        assert reason is None

    def test_critical_floor_overrides_high(self):
        cfg = make_compliance_config({"SOX": "critical"})
        sev, reason = cfg.effective_severity("high", ["SOX"])
        assert sev == "critical"
        assert reason == "SOX"

    def test_empty_frameworks_list(self):
        cfg = make_compliance_config({"PCI_DSS": "high"})
        sev, reason = cfg.effective_severity("low", [])
        assert sev == "low"
        assert reason is None


# ---------------------------------------------------------------------------
# match_to_finding — integration-style test (no I/O)
# ---------------------------------------------------------------------------

class TestMatchToFindingWithOverride:

    def test_low_confidence_pci_finding_elevated_to_high(self):
        """
        A Visa card number with score 0.35 (→ 'medium') and PCI_DSS:high
        override should appear as 'high' in the finding, but the confidence
        score must remain 0.35.
        """
        from dlp_scanner.scoring import match_to_finding
        from dlp_scanner.models import Location

        cfg = make_compliance_config({"PCI_DSS": "high"})
        match = make_match(score=0.35, rule_id="FIN_CREDIT_CARD_VISA")
        location = Location(source_type="file", uri="test.txt")

        finding = match_to_finding(
            match,
            text="card: 4111000011112222 exp",
            location=location,
            redaction_style="partial",
            compliance_config=cfg,
        )

        assert finding.severity == "high", (
            "PCI_DSS override should raise medium→high"
        )
        assert abs(finding.confidence - 0.35) < 1e-9, (
            "Confidence must not be changed by severity override"
        )
        assert "PCI_DSS" in finding.compliance_frameworks

    def test_no_override_config_leaves_severity_unchanged(self):
        """Without compliance_config, behaviour is identical to original."""
        from dlp_scanner.scoring import match_to_finding
        from dlp_scanner.models import Location

        match = make_match(score=0.22, rule_id="PII_EMAIL")
        location = Location(source_type="file", uri="test.txt")

        finding = match_to_finding(
            match,
            text="contact user@example.com please",
            location=location,
            redaction_style="partial",
            compliance_config=None,
        )

        # score 0.22 → "low" (below 0.40 medium threshold)
        assert finding.severity == "low"

    def test_compliance_config_none_is_default(self):
        """Omitting compliance_config entirely should work (default=None)."""
        from dlp_scanner.scoring import match_to_finding
        from dlp_scanner.models import Location

        match = make_match(score=0.50, rule_id="PII_SSN")
        location = Location(source_type="file", uri="test.txt")

        # Should not raise
        finding = match_to_finding(
            match,
            text="SSN: 123-45-6789 on file",
            location=location,
            redaction_style="full",
        )
        assert finding is not None


# ---------------------------------------------------------------------------
# Config loading — severity_overrides survives YAML round-trip
# ---------------------------------------------------------------------------

class TestConfigLoading:

    def test_severity_overrides_parsed_from_dict(self):
        """ComplianceConfig accepts severity_overrides from a plain dict."""
        cfg = ComplianceConfig(
            frameworks=["PCI_DSS", "HIPAA"],
            severity_overrides={"PCI_DSS": "high", "HIPAA": "medium"},
        )
        assert cfg.severity_overrides["PCI_DSS"] == "high"
        assert cfg.severity_overrides["HIPAA"] == "medium"

    def test_severity_overrides_defaults_to_empty(self):
        from dlp_scanner.config import ComplianceConfig
        cfg = ComplianceConfig()
        assert cfg.severity_overrides == {}

    def test_scan_config_passes_compliance_through(self):
        sc = ScanConfig(
            compliance=ComplianceConfig(
                severity_overrides={"PCI_DSS": "critical"}
            )
        )
        assert sc.compliance.severity_overrides["PCI_DSS"] == "critical"