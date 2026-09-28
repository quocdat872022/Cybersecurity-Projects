"""
©AngelaMos | 2026
test_splunk_hec_reporter.py
"""


import json
from unittest.mock import MagicMock, patch

import pytest

from dlp_scanner.models import Finding, Location, ScanResult
from dlp_scanner.reporters.splunk_hec_reporter import (
    HecSendError,
    SplunkHecReporter,
)


@pytest.fixture
def result_with_findings() -> ScanResult:
    result = ScanResult(targets_scanned=1)
    result.findings = [
        Finding(
            rule_id="CRED_AWS_ACCESS_KEY",
            rule_name="AWS Access Key ID",
            severity="high",
            confidence=0.85,
            location=Location(
                source_type="file",
                uri="config.json",
            ),
            redacted_snippet="AKIA****",
            compliance_frameworks=[],
            remediation="Rotate the key",
        ),
    ]
    return result


class TestSplunkHecReporterGenerate:
    def test_generate_never_touches_network(
        self, result_with_findings: ScanResult
    ) -> None:
        reporter = SplunkHecReporter(
            hec_url="https://splunk.invalid:8088",
            hec_token="fake-token",
        )
        with patch("urllib.request.urlopen") as mock_open:
            output = reporter.generate(result_with_findings)
            mock_open.assert_not_called()
        assert output

    def test_output_is_one_json_object_per_line(
        self, result_with_findings: ScanResult
    ) -> None:
        reporter = SplunkHecReporter()
        output = reporter.generate(result_with_findings)
        lines = output.split("\n")
        assert len(lines) == len(result_with_findings.findings) + 1
        for line in lines:
            json.loads(line)

    def test_finding_event_has_expected_fields(
        self, result_with_findings: ScanResult
    ) -> None:
        reporter = SplunkHecReporter(sourcetype="dlp:finding")
        output = reporter.generate(result_with_findings)
        finding_event = json.loads(output.split("\n")[1])
        assert finding_event["sourcetype"] == "dlp:finding"
        event = finding_event["event"]
        assert event["rule_id"] == "CRED_AWS_ACCESS_KEY"
        assert event["severity"] == "high"
        assert event["uri"] == "config.json"


class TestSplunkHecReporterSend:
    def test_requires_url_and_token(
        self, result_with_findings: ScanResult
    ) -> None:
        reporter = SplunkHecReporter()
        with pytest.raises(ValueError):
            reporter.send(result_with_findings)

    def test_send_posts_to_hec_endpoint(
        self, result_with_findings: ScanResult
    ) -> None:
        reporter = SplunkHecReporter(
            hec_url="https://splunk.example.com:8088",
            hec_token="secret-token",
            flush_interval=0,
        )

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch(
            "urllib.request.urlopen", return_value=mock_response
        ) as mock_urlopen:
            sent = reporter.send(result_with_findings)

        assert sent == len(result_with_findings.findings) + 1
        request = mock_urlopen.call_args[0][0]
        assert request.full_url == (
            "https://splunk.example.com:8088/services/collector/event"
        )
        assert request.headers["Authorization"] == "Splunk secret-token"

    def test_send_failure_raises_hec_send_error(
        self, result_with_findings: ScanResult
    ) -> None:
        import urllib.error

        reporter = SplunkHecReporter(
            hec_url="https://splunk.example.com:8088",
            hec_token="secret-token",
            batch_size=1,
            flush_interval=0,
        )

        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("no route to host"),
        ):
            with pytest.raises(HecSendError) as exc_info:
                reporter.send(result_with_findings)

        assert exc_info.value.sent_count == 0