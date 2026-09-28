"""
©AngelaMos | 2026
splunk_hec_reporter.py

Challenge 9: SIEM Integration via Syslog -- Splunk HEC transport

Alternative to syslog_reporter.py for shops that run Splunk and prefer
the HTTP Event Collector (HEC) over syslog. Uses only the standard
library (urllib) so no new project dependency is required.

Usage:

    reporter = SplunkHecReporter(
        hec_url = "https://splunk.corp.com:8088",
        hec_token = "11111111-2222-3333-4444-555555555555",
    )
    sent = reporter.send(result)

Each finding is posted as one Splunk HEC event::

    {
      "time": 1744104600.123,
      "host": "scanner-01",
      "source": "dlp-scan",
      "sourcetype": "dlp:finding",
      "event": {
        "scan_id": "...", "rule_id": "PII_SSN", "severity": "critical", ...
      }
    }

Events are batched: multiple JSON objects are concatenated (HEC's
native batching format -- no wrapping array, no separators needed)
into a single POST body, up to ``batch_size`` events per request.
"""

from __future__ import annotations

import json
import ssl as ssl_module
import time
import urllib.error
import urllib.request
from socket import gethostname
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from dlp_scanner.models import Finding, ScanResult


log = structlog.get_logger()

DEFAULT_BATCH_SIZE: int = 50
DEFAULT_FLUSH_INTERVAL_SECONDS: float = 5.0
DEFAULT_TIMEOUT_SECONDS: float = 10.0
DEFAULT_SOURCETYPE: str = "dlp:finding"
DEFAULT_SOURCE: str = "dlp-scan"
HEC_EVENT_PATH: str = "/services/collector/event"


class SplunkHecReporter:
    """
    Formats and optionally POSTs findings to a Splunk HTTP Event Collector

    Implements the Reporter protocol via ``generate(result) -> str``,
    which renders the same JSON payload that would be sent without
    making any network call. ``send(result)`` performs the actual POST.
    """
    def __init__(
        self,
        hec_url: str = "",
        hec_token: str = "",
        *,
        source: str = DEFAULT_SOURCE,
        sourcetype: str = DEFAULT_SOURCETYPE,
        host: str = "",
        batch_size: int = DEFAULT_BATCH_SIZE,
        flush_interval: float = DEFAULT_FLUSH_INTERVAL_SECONDS,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        verify_ssl: bool = True,
    ) -> None:
        self._hec_url = hec_url.rstrip("/")
        self._hec_token = hec_token
        self._source = source
        self._sourcetype = sourcetype
        self._host = host or gethostname()
        self._batch_size = max(1, batch_size)
        self._flush_interval = flush_interval
        self._timeout = timeout
        self._verify_ssl = verify_ssl

    # ── Reporter protocol ────────────────────────────────────────────────

    def generate(self, result: "ScanResult") -> str:
        """
        Render every HEC event as newline-delimited JSON, without sending
        """
        events = [self._build_summary_event(result)]
        events.extend(
            self._build_finding_event(f, result.scan_id)
            for f in result.findings
        )
        return "\n".join(json.dumps(e) for e in events)

    # ── Network delivery ─────────────────────────────────────────────────

    def send(self, result: "ScanResult") -> int:
        """
        POST the scan summary and every finding to the HEC endpoint

        Returns the number of events successfully accepted by Splunk.
        Raises HecSendError (wrapping the failed HTTP/URL error) if a
        batch is rejected; events already sent in prior batches remain
        counted via ``HecSendError.sent_count``.
        """
        if not self._hec_url or not self._hec_token:
            raise ValueError(
                "SplunkHecReporter.send() requires hec_url and "
                "hec_token"
            )

        events = [self._build_summary_event(result)]
        events.extend(
            self._build_finding_event(f, result.scan_id)
            for f in result.findings
        )

        sent = 0
        try:
            for batch_start in range(0, len(events), self._batch_size):
                batch = events[
                    batch_start : batch_start + self._batch_size
                ]
                self._post_batch(batch)
                sent += len(batch)

                is_last_batch = (
                    batch_start + self._batch_size >= len(events)
                )
                if not is_last_batch and self._flush_interval > 0:
                    time.sleep(self._flush_interval)

        except (urllib.error.URLError, OSError) as exc:
            log.warning(
                "splunk_hec_send_failed",
                hec_url = self._hec_url,
                sent_before_failure = sent,
                error = str(exc),
            )
            raise HecSendError(sent_count = sent) from exc

        log.info(
            "splunk_hec_send_complete",
            hec_url = self._hec_url,
            events_sent = sent,
        )
        return sent

    def _post_batch(self, batch: list[dict]) -> None:
        """
        POST a single batch of HEC events as concatenated JSON objects
        """
        body = "".join(json.dumps(event) for event in batch).encode(
            "utf-8"
        )

        request = urllib.request.Request(
            url = f"{self._hec_url}{HEC_EVENT_PATH}",
            data = body,
            method = "POST",
            headers = {
                "Authorization": f"Splunk {self._hec_token}",
                "Content-Type": "application/json",
            },
        )

        context = None
        if not self._verify_ssl:
            context = ssl_module.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl_module.CERT_NONE

        with urllib.request.urlopen(
            request,
            timeout = self._timeout,
            context = context,
        ) as response:
            if response.status >= 400:
                raise urllib.error.HTTPError(
                    self._hec_url,
                    response.status,
                    "HEC rejected event batch",
                    dict(response.headers),
                    None,
                )

    # ── Event formatting ─────────────────────────────────────────────────

    def _build_summary_event(self, result: "ScanResult") -> dict:
        """
        Build the scan-level summary HEC event
        """
        by_sev = result.findings_by_severity
        return {
            "time": result.scan_started_at.timestamp(),
            "host": self._host,
            "source": self._source,
            "sourcetype": "dlp:scan_summary",
            "event": {
                "scan_id": result.scan_id,
                "tool_version": result.tool_version,
                "targets_scanned": result.targets_scanned,
                "total_findings": len(result.findings),
                "by_severity": by_sev,
                "errors": result.errors,
            },
        }

    def _build_finding_event(
        self,
        finding: "Finding",
        scan_id: str,
    ) -> dict:
        """
        Build a single HEC event for one finding
        """
        return {
            "time": finding.detected_at.timestamp(),
            "host": self._host,
            "source": self._source,
            "sourcetype": self._sourcetype,
            "event": {
                "scan_id": scan_id,
                "finding_id": finding.finding_id,
                "rule_id": finding.rule_id,
                "rule_name": finding.rule_name,
                "severity": finding.severity,
                "confidence": round(finding.confidence, 4),
                "source_type": finding.location.source_type,
                "uri": finding.location.uri,
                "line": finding.location.line,
                "table_name": finding.location.table_name,
                "compliance_frameworks": finding.compliance_frameworks,
                "remediation": finding.remediation,
            },
        }


class HecSendError(RuntimeError):
    """
    Raised when a batch of HEC events is rejected or the connection fails
    """
    def __init__(self, sent_count: int) -> None:
        super().__init__(
            f"Splunk HEC send failed after {sent_count} event(s) "
            f"were successfully accepted"
        )
        self.sent_count = sent_count