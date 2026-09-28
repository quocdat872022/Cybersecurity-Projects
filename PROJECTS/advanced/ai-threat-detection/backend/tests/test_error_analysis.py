"""
©AngelaMos | 2026
test_error_analysis.py

Tests nginx error log parsing, body feature extraction,
access/error correlation, and the ErrorLogPipeline worker

Connects to:
  core/ingestion/error_parsers  - parse_error_line
  core/features/body_features   - extract_body_features
  core/enrichment/correlator    - EventCorrelator
  core/ingestion/error_pipeline - ErrorLogPipeline
"""

import asyncio
from datetime import UTC, datetime

import pytest

from app.core.enrichment.correlator import EventCorrelator
from app.core.features.body_features import extract_body_features
from app.core.ingestion.error_parsers import parse_error_line
from app.core.ingestion.error_pipeline import ErrorAnalysisResult, ErrorLogPipeline
from app.core.ingestion.parsers import ParsedLogEntry

BASIC_LINE = (
    "2026/03/15 09:22:31 [error] 7#7: *1234 upstream prematurely "
    "closed connection while reading response header from upstream, "
    'client: 93.184.216.34, server: _, request: "POST /api/login '
    'HTTP/1.1", host: "example.com"'
)

NO_CLIENT_LINE = "2026/03/15 09:22:31 [warn] 1#1: some generic warning"


def test_parse_basic_error_line() -> None:
    """
    A well-formed error line extracts all suffix fields correctly.
    """
    entry = parse_error_line(BASIC_LINE)
    assert entry is not None
    assert entry.timestamp == datetime(2026, 3, 15, 9, 22, 31, tzinfo=UTC)
    assert entry.level == "error"
    assert entry.pid == 7
    assert entry.tid == 7
    assert entry.connection_id == 1234
    assert entry.client_ip == "93.184.216.34"
    assert entry.request_method == "POST"
    assert entry.request_path == "/api/login"
    assert entry.host == "example.com"


def test_parse_line_without_client_fields() -> None:
    """
    Lines lacking client/request/host fields parse with those as None.
    """
    entry = parse_error_line(NO_CLIENT_LINE)
    assert entry is not None
    assert entry.level == "warn"
    assert entry.client_ip is None
    assert entry.request_method is None


def test_parse_malformed_line_returns_none() -> None:
    """
    Lines not matching the fixed nginx error format return None.
    """
    assert parse_error_line("not an nginx error line") is None


def test_parse_empty_line_returns_none() -> None:
    """
    Empty input returns None.
    """
    assert parse_error_line("") is None


def test_body_features_benign_text() -> None:
    """
    Plain text has low entropy and no attack pattern match.
    """
    features = extract_body_features("connection timed out")
    assert features["body_has_attack_pattern"] is False
    assert features["body_length"] == len("connection timed out")


def test_body_features_attack_payload() -> None:
    """
    Text containing an injection payload is flagged.
    """
    features = extract_body_features(
        "rejected body: ' UNION SELECT username,password FROM users--")
    assert features["body_has_attack_pattern"] is True
    assert features["body_entropy"] > 0.0


def _make_access_entry(ip: str, ts: datetime) -> ParsedLogEntry:
    return ParsedLogEntry(
        ip=ip,
        timestamp=ts,
        method="POST",
        path="/api/login",
        query_string="",
        status_code=502,
        response_size=0,
        referer="",
        user_agent="Mozilla/5.0",
        raw_line="",
    )


class TestEventCorrelator:
    """
    Test access/error correlation by IP and timestamp proximity
    """

    def test_matches_within_window(self) -> None:
        """
        An error correlates with an access entry inside the time window.
        """
        correlator = EventCorrelator(window_seconds=5.0)
        access_ts = datetime(2026, 3, 15, 9, 22, 30, tzinfo=UTC)
        correlator.record_access(
            _make_access_entry("93.184.216.34", access_ts))

        error = parse_error_line(BASIC_LINE)
        assert error is not None
        result = correlator.match_error(error)

        assert result.access is not None
        assert result.access.ip == "93.184.216.34"
        assert result.time_delta_seconds is not None
        assert result.time_delta_seconds <= 5.0

    def test_no_match_outside_window(self) -> None:
        """
        An error does not correlate with an access entry far outside the window.
        """
        correlator = EventCorrelator(window_seconds=5.0)
        far_ts = datetime(2026, 3, 15, 9, 0, 0, tzinfo=UTC)
        correlator.record_access(
            _make_access_entry("93.184.216.34", far_ts))

        error = parse_error_line(BASIC_LINE)
        assert error is not None
        result = correlator.match_error(error)

        assert result.access is None
        assert result.time_delta_seconds is None

    def test_no_match_without_client_ip(self) -> None:
        """
        Errors without a client field never correlate.
        """
        correlator = EventCorrelator()
        error = parse_error_line(NO_CLIENT_LINE)
        assert error is not None
        result = correlator.match_error(error)
        assert result.access is None


@pytest.mark.asyncio
async def test_error_pipeline_dispatches_result() -> None:
    """
    ErrorLogPipeline parses a queued line and dispatches an analysis result.
    """
    results: list[ErrorAnalysisResult] = []

    async def collect(result: ErrorAnalysisResult) -> None:
        results.append(result)

    queue: asyncio.Queue[str | None] = asyncio.Queue()
    pipeline = ErrorLogPipeline(
        error_queue=queue,
        correlator=EventCorrelator(),
        on_result=collect,
    )
    await pipeline.start()

    await queue.put(BASIC_LINE)
    await pipeline.stop()

    assert len(results) == 1
    assert results[0].error.client_ip == "93.184.216.34"
    assert "body_entropy" in results[0].body_features


@pytest.mark.asyncio
async def test_error_pipeline_skips_unparseable_lines() -> None:
    """
    Malformed lines don't crash the worker or produce a result.
    """
    results: list[ErrorAnalysisResult] = []

    async def collect(result: ErrorAnalysisResult) -> None:
        results.append(result)

    queue: asyncio.Queue[str | None] = asyncio.Queue()
    pipeline = ErrorLogPipeline(
        error_queue=queue,
        correlator=EventCorrelator(),
        on_result=collect,
    )
    await pipeline.start()

    await queue.put("garbage line")
    await queue.put(BASIC_LINE)
    await pipeline.stop()

    assert len(results) == 1