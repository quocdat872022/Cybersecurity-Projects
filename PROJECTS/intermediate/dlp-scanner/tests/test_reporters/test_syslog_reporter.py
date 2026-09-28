"""
©AngelaMos | 2026
test_syslog_reporter.py
"""


import socket
from unittest.mock import MagicMock, patch

import pytest

from dlp_scanner.models import Finding, Location, ScanResult
from dlp_scanner.reporters.syslog_reporter import (
    SyslogReporter,
    SyslogSendError,
    _build_structured_data,
    _escape_sd_value,
)


@pytest.fixture
def result_with_findings() -> ScanResult:
    result = ScanResult(targets_scanned=2)
    result.findings = [
        Finding(
            rule_id="PII_SSN",
            rule_name="US Social Security Number",
            severity="critical",
            confidence=0.95,
            location=Location(
                source_type="file",
                uri="employees.csv",
                line=2,
            ),
            redacted_snippet="***-**-6789",
            compliance_frameworks=["HIPAA", "CCPA"],
            remediation="Encrypt SSN data",
        ),
        Finding(
            rule_id="PII_EMAIL",
            rule_name="Email Address",
            severity="medium",
            confidence=0.65,
            location=Location(
                source_type="file",
                uri="contacts.json",
            ),
            redacted_snippet="j***@example.com",
            compliance_frameworks=["GDPR"],
            remediation="Hash emails",
        ),
    ]
    return result


class TestStructuredData:
    def test_escapes_backslash_quote_bracket(self) -> None:
        value = _escape_sd_value('a"b\\c]d')
        assert value == 'a\\"b\\\\c\\]d'

    def test_nil_value_for_empty_params(self) -> None:
        assert _build_structured_data("finding@dlp", {}) == "-"

    def test_renders_params(self) -> None:
        sd = _build_structured_data(
            "finding@dlp", {"rule_id": "PII_SSN", "severity": "critical"}
        )
        assert sd == '[finding@dlp rule_id="PII_SSN" severity="critical"]'


class TestSyslogReporterGenerate:
    def test_generate_never_touches_network(
        self, result_with_findings: ScanResult
    ) -> None:
        reporter = SyslogReporter(host="unused.invalid")
        with patch("socket.create_connection") as mock_conn:
            output = reporter.generate(result_with_findings)
            mock_conn.assert_not_called()
        assert output

    def test_one_line_per_finding_plus_summary(
        self, result_with_findings: ScanResult
    ) -> None:
        reporter = SyslogReporter()
        output = reporter.generate(result_with_findings)
        lines = output.split("\n")
        assert len(lines) == len(result_with_findings.findings) + 1

    def test_messages_are_rfc5424_shaped(
        self, result_with_findings: ScanResult
    ) -> None:
        reporter = SyslogReporter()
        output = reporter.generate(result_with_findings)
        finding_line = output.split("\n")[1]
        assert finding_line.startswith("<")
        pri_and_version = finding_line.split(" ", 1)[0]
        assert pri_and_version.endswith(">1")  # no space before VERSION
        assert "PII_SSN" in finding_line
        assert 'rule_id="PII_SSN"' in finding_line

    def test_severity_reflected_in_pri(
        self, result_with_findings: ScanResult
    ) -> None:
        reporter = SyslogReporter()
        output = reporter.generate(result_with_findings)
        finding_line = output.split("\n")[1]
        pri = int(finding_line.split(">")[0].lstrip("<"))
        # facility 16 (local0) * 8 + severity 2 (critical) = 130
        assert pri == 130

    def test_clean_scan_summary(self) -> None:
        reporter = SyslogReporter()
        result = ScanResult(targets_scanned=3)
        output = reporter.generate(result)
        assert "0 findings" in output

    def test_rejects_unknown_protocol(self) -> None:
        with pytest.raises(ValueError):
            SyslogReporter(protocol="quic")


class TestSyslogReporterSend:
    def test_requires_host(
        self, result_with_findings: ScanResult
    ) -> None:
        reporter = SyslogReporter()
        with pytest.raises(ValueError):
            reporter.send(result_with_findings)

    def test_tcp_send_uses_socket(
        self, result_with_findings: ScanResult
    ) -> None:
        reporter = SyslogReporter(
            host="siem.example.com",
            port=1514,
            protocol="tcp",
            flush_interval=0,
        )
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        with patch(
            "socket.create_connection", return_value=mock_sock
        ) as mock_conn:
            sent = reporter.send(result_with_findings)

        mock_conn.assert_called_once_with(
            ("siem.example.com", 1514), timeout=5.0
        )
        mock_sock.sendall.assert_called_once()
        assert sent == len(result_with_findings.findings) + 1

    def test_udp_send_uses_datagrams(
        self, result_with_findings: ScanResult
    ) -> None:
        reporter = SyslogReporter(
            host="siem.example.com",
            port=514,
            protocol="udp",
            flush_interval=0,
        )
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        with patch("socket.socket", return_value=mock_sock):
            sent = reporter.send(result_with_findings)

        assert mock_sock.sendto.call_count == (
            len(result_with_findings.findings) + 1
        )
        assert sent == len(result_with_findings.findings) + 1

    def test_send_failure_raises_and_reports_partial_count(
        self, result_with_findings: ScanResult
    ) -> None:
        reporter = SyslogReporter(
            host="siem.example.com",
            protocol="tcp",
            batch_size=1,
            flush_interval=0,
        )

        with patch(
            "socket.create_connection",
            side_effect=OSError("connection refused"),
        ):
            with pytest.raises(SyslogSendError) as exc_info:
                reporter.send(result_with_findings)

        assert exc_info.value.sent_count == 0